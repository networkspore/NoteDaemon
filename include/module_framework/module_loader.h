// include/module_framework/module_loader.h
// Module discovery and dynamic loading

#ifndef MODULE_LOADER_H
#define MODULE_LOADER_H

#include <string>
#include <variant>
#include <string_view>
#include <vector>
#include "imodule.h"
#include "error.h"

namespace NoteDaemon {

/**
 * Module loader - discovers and loads modules from the filesystem
 */
class ModuleLoader {
public:
    ModuleLoader() = default;
    ~ModuleLoader() = default;
    
    // Prevent copying
    ModuleLoader(const ModuleLoader&) = delete;
    ModuleLoader& operator=(const ModuleLoader&) = delete;

    /**
     * Discover all modules in the given directory
     * Looks for directories containing config.json and <module_name>.so
     * 
     * @param module_dir The directory to scan (e.g., "/etc/netnotes/modules")
     * @return Vector of module info (name, path, config)
     */
    struct ModuleInfo {
        std::string name;           // Module ID (e.g., "note_usb")
        std::string config_path;   // Path to config.json
        std::string so_path;       // Path to .so file
        std::string base_path;     // Directory containing module files
    };
    
    std::vector<ModuleInfo> discover_modules(std::string_view module_dir);
    
    /**
     * Load a single module from its .so file.
     * Ownership is retained by ModuleLoader until unload_module()/unload_all().
     *
     * @param info Module information from discover_modules
     * @return Loaded IModule pointer, or error
     */
    std::variant<IModule*, Error> load_module(const ModuleInfo& info);
    
    /**
     * Load all discovered modules.
     * Ownership is retained by ModuleLoader.
     *
     * @param module_dir Directory to scan
     * @return Vector of loaded module pointers (errors logged but skipped)
     */
    std::vector<IModule*> load_all(std::string_view module_dir);
    
    /**
     * Unload a module (calls shutdown and dlclose for that module).
     *
     * @param module Module to unload
     */
    void unload_module(IModule* module);
    
    /**
     * Unload all loaded modules
     */
    void unload_all();

private:
    struct LoadedModule {
        std::string name;
        IModule* module;
        void* handle;  // dlopen handle for later unloading
    };
    
    std::vector<LoadedModule> loaded_modules_;
    
    Error load_module_from_so(const ModuleInfo& info, IModule*& out_module, void*& out_handle);
    std::string find_module_so(const std::string& base_path, const std::string& module_name);
};

/**
 * Module not found error
 */
inline Error make_module_not_found_error(const std::string& module_name) {
    return Error::from_code(ErrorCodes::MODULE_NOT_FOUND,
                            "Module not found: " + module_name,
                            "module_loader");
}

/**
 * Module load failed error
 */
inline Error make_module_load_error(const std::string& module_name, const std::string& reason) {
    return Error::from_code(ErrorCodes::MODULE_LOAD_FAILED,
                            "Failed to load module " + module_name + ": " + reason,
                            "module_loader");
}

/**
 * Module symbol not found error
 */
inline Error make_symbol_not_found_error(const std::string& module_name) {
    return Error::from_code(ErrorCodes::MODULE_SYMBOL_NOT_FOUND,
                            "Module factory symbol not found in: " + module_name,
                            "module_loader");
}

} // namespace NoteDaemon

#endif // MODULE_LOADER_H
