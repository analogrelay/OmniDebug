class ConfigFileEntry():
    def __init__(self, source: str, target: str, roots: list[str], ppout: str, enabled: bool):
        self.source = source
        self.target = target
        self.roots = roots
        self.ppout = ppout
        self.enabled = enabled

    def from_json(json_obj):
        source = json_obj["source"]
        target = json_obj["target"]
        roots = json_obj["roots"]
        ppout = json_obj["ppout"]
        enabled = json_obj.get("enabled", True)
        return ConfigFileEntry(source, target, roots, ppout, enabled)

class ConfigWrapperEntry():
    def __init__(self, name: str, target: str, ifaces: list[str]):
        self.name = name
        self.target = target
        self.ifaces = ifaces
    
    def from_json(json_obj):
        name = json_obj["name"]
        target = json_obj["target"]
        ifaces = json_obj["interfaces"]
        return ConfigWrapperEntry(name, target, ifaces)

class Configuration():
    def __init__(self, mapped_types: dict[str, str], clang_args: list[str], include_paths: list[str], defines: dict[str, str], files: list[ConfigFileEntry], roots: list[str], wrappers: list[ConfigWrapperEntry]):
        self.mapped_types = mapped_types
        self.clang_args = clang_args
        self.include_paths = include_paths
        self.defines = defines
        self.files = files
        self.roots = roots
        self.wrappers = wrappers

    def from_json(json):
        mapped_types = json.get('mapped_types') or {}
        clang_args = json.get('clang_args') or []
        include_paths = json.get('include_paths') or []
        defines = json.get('defines') or []
        files = [ ConfigFileEntry.from_json(x) for x in json.get('files') or [] ]
        roots = json.get('roots') or []
        wrappers = [ ConfigWrapperEntry.from_json(x) for x in json.get('wrappers') or [] ]
        return Configuration(mapped_types, clang_args, include_paths, defines, files, roots, wrappers)