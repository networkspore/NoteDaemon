// include/module_framework/path_resolver.h
// Centralized, root-relative directory resolution for Netnotes.
//
// All important paths are derived from a single root directory:
//   - modules
//   - logs
//   - runtime
//   - note_usb/device_registry (discovery + capabilities)
//
// The note_usb paths are runtime data paths consumed by the external
// NoteUSB module project, while core remains module-agnostic.
//
// Resolution priority:
//   1) CLI argument (--root)
//   2) Environment variable (NETNOTES_ROOT)
//   3) Config file (root.path)
//   4) Platform default

#ifndef PATH_RESOLVER_H
#define PATH_RESOLVER_H

#include <string>
#include <vector>
#include <filesystem>

namespace NoteDaemon {

struct Paths {
    // Root directory for all Netnotes data
    std::string root;

    // Derived directories (relative to root)
    std::string modules_dir;
    std::string logs_dir;
    std::string runtime_dir;

    // NoteUSB-specific
    std::string note_usb_registry_dir;          // note_usb/device_registry
    std::string note_usb_discovery_registry_file; // note_usb/device_registry/discovery.json

    // Legacy / crash-recovery (can be merged later)
    std::string note_usb_crash_registry_file;   // runtime/note_usb/device_registry.json
};

/**
 * Resolve the canonical root directory using:
 *   1) explicit_root (e.g. from CLI --root)
 *   2) env var NETNOTES_ROOT
 *   3) config_root (from config file root.path)
 *   4) platform default
 *
 * Ensures the path is absolute and exists (creates if needed).
 */
std::string resolve_root(std::string_view explicit_root,
                         std::string_view config_root);

/**
 * Build the full Paths structure from a resolved root.
 * Creates subdirectories as needed.
 */
Paths build_paths(const std::string& root);

/**
 * Utility: join paths (cross-platform friendly).
 */
std::string join_path(std::string_view base, std::string_view rel);

/**
 * Utility: ensure directory exists (recursive).
 */
bool ensure_dir(const std::string& path);

} // namespace NoteDaemon

#endif // PATH_RESOLVER_H
