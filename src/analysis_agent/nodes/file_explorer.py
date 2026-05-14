"""FileExplorer node — pure heuristic, no LLM call needed."""
from analysis_agent.state import AnalysisState
from analysis_agent.tools.filesystem import find_files_by_name, list_directory, read_file

# Files that are strong signals for build system / project type
_KEY_FILE_NAMES = [
    # Build systems
    "CMakeLists.txt", "Makefile", "makefile", "GNUmakefile",
    "build.gradle", "build.gradle.kts", "pom.xml",
    "Cargo.toml", "go.mod",
    "package.json", "webpack.config.js",
    "meson.build", "SConstruct", "Jamfile",
    # MSBuild / Visual Studio
    "*.sln", "*.vcxproj", "*.csproj",
    # CI/CD
    "Jenkinsfile", "Dockerfile", ".travis.yml",
    "azure-pipelines.yml", "bitbucket-pipelines.yml",
    # Docs
    "README.md", "README.txt", "README",
    "BUILDING.md", "BUILD.md", "INSTALL.md",
]

# Exact names (no glob)
_EXACT_NAMES = [
    "CMakeLists.txt", "Makefile", "makefile", "GNUmakefile",
    "build.gradle", "build.gradle.kts", "pom.xml",
    "Cargo.toml", "go.mod", "package.json",
    "meson.build", "SConstruct",
    "Jenkinsfile", "Dockerfile",
    "README.md", "README.txt", "README",
    "BUILDING.md", "BUILD.md", "INSTALL.md",
    "webpack.config.js", "CMakePresets.json",
]

# Extension-based role detection
_EXT_TO_ROLE = {
    ".sln": "vs_solution",
    ".vcxproj": "vs_vcxproj",
    ".csproj": "vs_csproj",
}


def _detect_role(name: str) -> str:
    role_map = {
        "CMakeLists.txt": "cmake",
        "Makefile": "makefile", "makefile": "makefile", "GNUmakefile": "makefile",
        "build.gradle": "gradle", "build.gradle.kts": "gradle",
        "pom.xml": "maven",
        "Cargo.toml": "cargo",
        "go.mod": "gomod",
        "package.json": "npm",
        "meson.build": "meson",
        "Jenkinsfile": "jenkinsfile",
        "Dockerfile": "dockerfile",
        "README.md": "readme", "README.txt": "readme", "README": "readme",
        "BUILDING.md": "build_doc", "BUILD.md": "build_doc", "INSTALL.md": "build_doc",
        "webpack.config.js": "webpack",
        "CMakePresets.json": "cmake_presets",
    }
    return role_map.get(name, "other")


def file_explorer_node(state: AnalysisState) -> dict:
    repo_path = state["repo_path"]

    try:
        file_tree = list_directory(repo_path, max_depth=5)
    except Exception as e:
        return {"file_tree": [], "key_files": {}, "readme_content": "", "errors": [f"file_explorer: {e}"]}

    # Find exact-name key files
    found = find_files_by_name(repo_path, _EXACT_NAMES)
    key_files: dict[str, str] = {}
    for name, rel_path in found.items():
        role = _detect_role(name)
        if role not in key_files:
            key_files[role] = rel_path

    # Detect extension-based key files not already found
    for rel in file_tree:
        from pathlib import Path
        ext = Path(rel).suffix.lower()
        role = _EXT_TO_ROLE.get(ext)
        if role and role not in key_files:
            key_files[role] = rel

    # Read README
    readme_content = ""
    for readme_role in ("readme", "build_doc"):
        if readme_role in key_files:
            readme_content = read_file(repo_path, key_files[readme_role], max_bytes=8192)
            if readme_content:
                break

    return {
        "file_tree": file_tree,
        "key_files": key_files,
        "readme_content": readme_content,
        "completed_nodes": ["file_explorer"],
        "errors": [],
    }
