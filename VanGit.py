import argparse
import collections
import difflib
import enum
import hashlib
import operator
import os
import stat
import struct
import sys
import time
import zlib

# git索引(.git/index)中的数据
# 相当于只有属性没有方法的类
IndexEntry = collections.namedtuple('IndexEntry',
                                    [
                                        'ctime_s', 'ctime_n', 'mtime_s', 'mtime_n', 'dev', 'ino', 'mode', 'uid',
                                        'gid', 'size', 'sha1', 'flags', 'path',
                                    ])


class ObjectType(enum.Enum):
    """
    enum,Git对象的类型 -> blobs, commits, trees
    """
    commit = 1
    tree = 2
    blob = 3


def read_file(path):
    """
    读取path指向的文件
    :param path:文件路径
    :return data:byte data 文件数据
    """
    with open(path, 'rb') as f:
        return f.read()


def write_file(path, data):
    """
    将byte data写入path指向的文件
    :param path:文件路径
    :param data:写入数据
    """
    with open(path, 'wb') as f:
        f.write(data)


def init(repo):
    """
    初始化 .git 目录
    :param repo:根文件路径
    :return:
    """
    os.mkdir(repo)
    os.mkdir(os.path.join(repo, '.git'))

    for name in ['objects', 'refs', 'refs/heads']:
        os.mkdir(os.path.join(repo, '.git', name))

    write_file(os.path.join(repo, '.git', 'HEAD'), b'ref: refs/heads/master')
    print('initialized empty repository: {}'.format(repo))


def hash_object(data, object_type, write=True):
    """
    计算给定类型对象数据的哈希值并写入IndexEntry
    如果“写”为真,将SHA-1 hash作为十六进制字符串返回
    :param data:byte 数据
    :param object_type:Git对象的类型 -> blobs, commits, trees
    :param write:标志位,是否写入
    :return sha1:hash ID
    """
    header = '{} {}'.format(object_type, len(data)).encode()
    full_data = header + b'\x00' + data
    sha1 = hashlib.sha1(full_data).hexdigest()
    if write:
        path = os.path.join('.git', 'objects', sha1[:2], sha1[2:])
        if not os.path.exists(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            write_file(path, zlib.compress(full_data))
    return sha1


def find_object(sha1_prefix):
    """
    查找具有给定SHA-1前缀的对象并返回对象中对象的路径
    如果没有对象或多个对象，则引发ValueError带有这个SHA-1前缀
    :param sha1_prefix:SHA-1前缀
    :return:具有SHA-1前缀对象的路径
    """
    if len(sha1_prefix) < 2:
        raise ValueError('哈希前缀必须是2个或更多字符')
    obj_dir = os.path.join('.git', 'objects', sha1_prefix[:2])
    rest = sha1_prefix[2:]
    objects = [name for name in os.listdir(obj_dir) if name.startswith(rest)]
    if not objects:
        raise ValueError('object {!r} not found'.format(sha1_prefix))
    if len(objects) >= 2:
        raise ValueError('多个 objects ({}) 带有前缀 {!r}'.format(
            len(objects), sha1_prefix))
    return os.path.join(obj_dir, objects[0])


def read_object(sha1_prefix):
    """
    读取具有给定SHA-1前缀的对象并返回元组(object_type, data_bytes)
    如果未找到，则引发 ValueError。
    :param sha1_prefix:SHA-1前缀
    :return (object_type, data_bytes):返回以sha1_prefix为SHA-1前缀对象的data&type
    """
    path = find_object(sha1_prefix)
    full_data = zlib.decompress(read_file(path))
    nul_index = full_data.index(b'\x00')
    header = full_data[:nul_index]
    obj_type, size_str = header.decode().split()
    size = int(size_str)
    data = full_data[nul_index + 1:]
    assert size == len(data), '预期大小 {}，得到 {} 个字节'.format(
        size, len(data))
    return (obj_type, data)


def cat_file(mode, sha1_prefix):
    """
    将具有给定 SHA-1 前缀的对象的内容（或信息）进行标准输出
    如果 mode 是 'commit'、'tree' 或 'blob'，则打印对象的数据字节
    如果模式是'size'，则打印对象的大小
    如果模式是'type',则打印对象的类型
    如果模式是'pretty'，则打印一个对象的美化版本
    :param mode:'commit', 'tree', 'blob', 'size', 'type', 'pretty'
    :param sha1_prefix:SHA-1前缀
    """
    obj_type, data = read_object(sha1_prefix)
    if mode in ['commit', 'tree', 'blob']:
        if obj_type != mode:
            raise ValueError('expected object type {}, get {}'.format(
                mode, obj_type))
        # 标准输出
        sys.stdout.buffer.write(data)
    elif mode == 'size':
        print(len(data))
    elif mode == 'type':
        print(obj_type)
    elif mode == 'pretty':
        if obj_type in ['commit', 'blob']:
            sys.stdout.buffer.write(data)
        elif obj_type == 'tree':
            for mode, path, sha1 in read_tree(data=data):
                type_str = 'tree' if stat.S_ISDIR(mode) else 'blob'
                print('{:06o} {} {}\t{}'.format(mode, type_str, sha1, path))
        else:
            assert False, 'unhandled object type {!r}'.format(obj_type)
    else:
        raise ValueError('unexpected mode {!r}'.format(mode))


def read_index():
    """
    读取 git 索引文件并返回 IndexEntry 对象列表。
    git index 前12字节为标头,末尾20字节为SHA-1,其余字节每隔62字节添加路径数据
    :return entries:IndexEntry 对象列表
    """
    try:
        data = read_file(os.path.join('.git', 'index'))
    except FileNotFoundError:
        return []
    # 设置git index
    digset = hashlib.sha1(data[:-20]).digest()  # 后20字节为SHA-1
    assert digset == data[-20:], 'invalid index checksum'
    # 签名、版本、条目数
    signature, version, num_entries = struct.unpack('!4sLL', data[:12])  # 前12字节为标头,4sLL -> 12字节 -> 4*char + long + long
    assert signature == b'DIRC', 'invalid index signature {}'.format(signature)
    assert version == 2, 'unknown index version {}'.format(version)
    # 数据
    entry_data = data[12:-20]
    entries = []
    i = 0
    while i + 62 < len(entry_data):
        fields_end = i + 62
        # LLLLLLLLLL20sH -> 62字节 -> 10*long + 20*char + short
        fields = struct.unpack('!LLLLLLLLLL20sH', entry_data[i:fields_end])
        path_end = entry_data.index(b'\x00', fields_end)
        path = entry_data[fields_end:path_end]
        entry = IndexEntry(*(fields + (path.decode(),)))
        entries.append(entry)
        entry_len = ((62 + len(path) + 8) // 8) * 8
        i += entry_len
    assert len(entries) == num_entries
    return entries


def ls_files(details=False):
    """
    打印IndexEntry中的所有文件（以及它们的模式和哈希，如果 -s已指定）
    :param details: -s 是否被指定
    :return:
    """
    for entry in read_index():
        if details:
            stage = (entry.flags >> 12) & 3
            print('{:6o} {} {:}\t{}'.format(entry.mode, entry.sha1.hex(), stage, entry.path))
        else:
            print(entry.path)


def get_status():
    """
    将IndexEntry中的文件与当前目录树中的文件进行比较,获取工作的状态
    :return (sorted(changed), sorted(new), sorted(deleted)):status 工作的状态
    """
    paths = set()
    for root, dirs, files in os.walk('.'):
        dirs[:] = [d for d in dirs if d != '.git']
        for file in files:
            path = os.path.join(root, file)
            path = path.replace('\\', '/')
            if path.startswith('./'):
                path = path[2:]
            paths.add(path)
    entries_by_path = {e.path: e for e in read_index()}
    entry_paths = set(entries_by_path)
    changed = {p for p in (paths & entry_paths)
                               if hash_object(read_file(p), 'blob', write=False) !=
                               entries_by_path[p].sha1.hex()}
    new = paths - entry_paths
    deleted = entry_paths - paths
    return (sorted(changed), sorted(new), sorted(deleted))


def status():
    """
    显示git状态，打印出哪些文件被修改、新建和删除
    """
    changed, new, deleted = get_status()
    if changed:
        print('changed files:')
        for path in changed:
            print('   ', path)
    if new:
        print('new files:')
        for path in new:
            print('   ', path)
    if deleted:
        print('deleted files:')
        for path in deleted:
            print('   ', path)


def diff():
    """
    打印每个修改文件的差异
    """
    changed, _, _ = get_status()
    entries_by_path = {e.path: e for e in read_index()}
    for i, path in enumerate(changed):
        sha1 = entries_by_path[path].sha1.hex()
        obj_type, data = read_object(sha1)
        assert obj_type == 'blob'
        index_lines = data.decode().splitlines()
        working_lines = read_file(path).decode().splitlines()
        diff_lines = difflib.unified_diff(
            index_lines, working_lines,
            '{} (index)'.format(path),
            '{} (working copy)'.format(path),
            lineterm='')
        for line in diff_lines:
            print(line)
        if i < len(changed) - 1:
            print('-' * 70)


def write_index(entries):
    """
    将 IndexEntry 对象列表写入 git 索引文件
    :param entries:IndexEntry 对象列表
    """
    packed_entries = []
    for entry in entries:
        entry_head = struct.pack('!LLLLLLLLLL20sH',
                                 entry.ctime_s, entry.ctime_n, entry.mtime_s, entry.mtime_n,
                                 entry.dev, entry.ino, entry.mode, entry.uid, entry.gid,
                                 entry.size, entry.sha1, entry.flags)
        path = entry.path.encode()
        length = ((62 + len(path) + 8) // 8) * 8
        packed_entry = entry_head + path + b'\x00' * (length - 62 - len(path))
        packed_entries.append(packed_entry)
    header = struct.pack('!4sLL', b'DIRC', 2, len(entries))
    all_data = header + b''.join(packed_entries)
    digest = hashlib.sha1(all_data).digest()
    write_file(os.path.join('.git', 'index'), all_data + digest)


def add(paths):
    """
    将所有文件路径添加到 git index
    :param paths:文件路径
    """
    paths = [p.replace('\\', '/') for p in paths]
    all_entries = read_index()
    entries = [e for e in all_entries if e.path not in paths]
    for path in paths:
        sha1 = hash_object(read_file(path), 'blob')
        st = os.stat(path)
        flags = len(path.encode())
        assert flags < (1 << 12)
        entry = IndexEntry(
            int(st.st_ctime), 0, int(st.st_mtime), 0, st.st_dev,
            st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_size,
            bytes.fromhex(sha1), flags, path)
        entries.append(entry)
        print('Add Succeed')
    entries.sort(key=operator.attrgetter('path'))
    write_index(entries)


def write_tree():
    """
    从当前IndexEntry写入树对象
    :return:hash ID tree
    """
    tree_entries = []
    for entry in read_index():
        assert '/' not in entry.path, '当前仅支持单个顶级目录'
        mode_path = '{:o} {}'.format(entry.mode, entry.path).encode()
        tree_entry = mode_path + b'\x00' + entry.sha1
        tree_entries.append(tree_entry)
    return hash_object(b''.join(tree_entries), 'tree')


def read_tree(sha1=None, data=None):
    """Read tree object with given SHA-1 (hex string) or data, and return list
    of (mode, path, sha1) tuples.
    """
    if sha1 is not None:
        obj_type, data = read_object(sha1)
        assert obj_type == 'tree'
    elif data is None:
        raise TypeError('must specify "sha1" or "data"')
    i = 0
    entries = []
    for _ in range(1000):
        end = data.find(b'\x00', i)
        if end == -1:
            break
        mode_str, path = data[i:end].decode().split()
        mode = int(mode_str, 8)
        digest = data[end + 1:end + 21]
        entries.append((mode, path, digest.hex()))
        i = end + 1 + 20
    return entries


def get_local_master_hash():
    """
    获取本地主分支当前的提交Hash（SHA-1 字符串）
    :return SHA1 String:主分支当前的提交Hash || None
    """
    master_path = os.path.join('.git', 'refs', 'heads', 'master')
    try:
        return read_file(master_path).decode().strip()
    except FileNotFoundError:
        return None


def commit(message, author=None):
    """
    使用给定的消息将索引的当前状态提交给 master。
    返回提交对象的哈希
    :param message:commit信息
    :param author:提交者信息
    :return sha1:commit SHA-1 hash ID
    """
    tree = write_tree()  # 当前目录（或IndexEntry）的快照,tree object
    parent = get_local_master_hash()  # 上一节点
    if author is None:
        author = '{} <{}>'.format('MorbidArk', '1482506841@qq.com')
    timestamp = int(time.mktime(time.localtime()))
    utc_offset = -time.timezone
    author_time = '{} {}{:02}{:02}'.format(timestamp,
                                           '+' if utc_offset > 0 else '-',
                                           abs(utc_offset) // 3600,
                                           (abs(utc_offset) // 60) % 60)
    lines = ['tree' + tree]
    if parent:
        lines.append('parent ' + parent)
    lines.append('author {} {}'.format(author, author_time))
    lines.append('committer {} {}'.format(author, author_time))
    lines.append('')
    lines.append(message)
    lines.append('')
    data = '\n'.join(lines).encode()
    sha1 = hash_object(data, 'commit')
    master_path = os.path.join('.git', 'refs', 'heads', 'master')
    write_file(master_path, (sha1 + '\n').encode())
    print('committed to master: {:7}'.format(sha1))
    return sha1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    sub_parsers = parser.add_subparsers(dest='command', metavar='command')
    sub_parsers.required = True

    sub_parser = sub_parsers.add_parser('add',
                                        help='add file(s) to index')
    sub_parser.add_argument('paths', nargs='+', metavar='path',
                            help='path(s) of files to add')

    sub_parser = sub_parsers.add_parser('cat-file',
                                        help='display contents of object')
    valid_modes = ['commit', 'tree', 'blob', 'size', 'type', 'pretty']
    sub_parser.add_argument('mode', choices=valid_modes,
                            help='object type (commit, tree, blob) or display mode (size, '
                                 'type, pretty)')
    sub_parser.add_argument('hash_prefix',
                            help='SHA-1 hash (or hash prefix) of object to display')

    sub_parser = sub_parsers.add_parser('commit',
                                        help='commit current state of index to master branch')
    sub_parser.add_argument('-a', '--author',
                            help='commit author in format "A U Thor <author@example.com>" '
                                 '(uses GIT_AUTHOR_NAME and GIT_AUTHOR_EMAIL environment '
                                 'variables by default)')
    sub_parser.add_argument('-m', '--message', required=True,
                            help='text of commit message')

    sub_parser = sub_parsers.add_parser('diff',
                                        help='show diff of files changed (between index and working '
                                             'copy)')

    sub_parser = sub_parsers.add_parser('hash-object',
                                        help='hash contents of given path (and optionally write to '
                                             'object store)')
    sub_parser.add_argument('path',
                            help='path of file to hash')
    sub_parser.add_argument('-t', choices=['commit', 'tree', 'blob'],
                            default='blob', dest='type',
                            help='type of object (default %(default)r)')
    sub_parser.add_argument('-w', action='store_true', dest='write',
                            help='write object to object store (as well as printing hash)')

    sub_parser = sub_parsers.add_parser('init',
                                        help='initialize a new repo')
    sub_parser.add_argument('repo',
                            help='directory name for new repo')

    sub_parser = sub_parsers.add_parser('ls-files',
                                        help='list files in index')
    sub_parser.add_argument('-s', '--stage', action='store_true',
                            help='show object details (mode, hash, and stage number) in '
                                 'addition to path')

    sub_parser = sub_parsers.add_parser('status',
                                        help='show status of working copy')

    args = parser.parse_args()
    if args.command == 'add':
        add(args.paths)
    elif args.command == 'cat-file':
        try:
            cat_file(args.mode, args.hash_prefix)
        except ValueError as error:
            print(error, file=sys.stderr)
            sys.exit(1)
    elif args.command == 'commit':
        commit(args.message, author=args.author)
    elif args.command == 'diff':
        diff()
    elif args.command == 'hash-object':
        sha1 = hash_object(read_file(args.path), args.type, write=args.write)
        print(sha1)
    elif args.command == 'init':
        init(args.repo)
    elif args.command == 'ls-files':
        ls_files(details=args.stage)
    elif args.command == 'status':
        status()
    else:
        assert False, 'unexpected command {!r}'.format(args.command)
