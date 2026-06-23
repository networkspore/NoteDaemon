// include/module_framework/module_registry.h
// Track and access loaded modules

#ifndef MODULE_REGISTRY_H
#define MODULE_REGISTRY_H

#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include "imodule.h"
#include "error.h"

// Forward declaration only — notebytes.h has heavy Boost dependencies.
namespace NoteBytes { class Object; }

namespace NoteDaemon {

/**
 * Module registry - tracks all loaded modules
 * Provides access by name and iteration
 */
class ModuleRegistry {
public:
    ModuleRegistry() = default;
    ~ModuleRegistry() = default;
    
    // Prevent copying
    ModuleRegistry(const ModuleRegistry&) = delete;
    ModuleRegistry& operator=(const ModuleRegistry&) = delete;

    /**
     * Register a module
     * 
     * @param module Module to register (must not be null)
     * @return Error::success() or error if already registered
     */
    Error register_module(IModule* module);
    
    /**
     * Unregister a module by name
     * 
     * @param module_name Name of module to unregister
     * @return Error::success() or error if not found
     */
    Error unregister_module(std::string_view module_name);
    
    /**
     * Get a module by name
     * 
     * @param module_name Name of the module
     * @return Pointer to module, or nullptr if not found
     */
    IModule* get(std::string_view module_name) const;
    
    /**
     * Check if a module is registered
     * 
     * @param module_name Name of the module
     * @return true if registered
     */
    bool has(std::string_view module_name) const;
    
    /**
     * Get all registered module names
     * 
     * @return Vector of module names
     */
    std::vector<std::string> get_module_names() const;
    
    /**
     * Get count of registered modules
     * 
     * @return Number of modules
     */
    size_t size() const;
    
    /**
     * Get all registered modules as pointers
     * 
     * @return Vector of module pointers (registry is non-owning)
     */
    std::vector<IModule*> get_all_modules() const;
    
    /**
     * Clear all registered modules (non-owning pointers only)
     */
    void clear();
    
    /**
     * Iterate over all modules
     * 
     * @param fn Function called with (name, module) for each module
     */
    template<typename Func>
    void for_each(Func&& fn) const {
        for (const auto& [name, module] : modules_) {
            fn(name, module);
        }
    }

    // ── Inter-module RPC ──────────────────────────────────────────────
    /** Send a NoteBytes message to a named module and get a response. */
    NoteBytes::Object send_to_module(const std::string& target_module,
                                      const NoteBytes::Object& msg);

private:
    std::unordered_map<std::string, IModule*> modules_;
};

/**
 * Module not registered error
 */
inline Error make_module_not_registered_error(const std::string& module_name) {
    return Error::from_code(ErrorCodes::MODULE_NOT_REGISTERED,
                            "Module not registered: " + module_name,
                            "module_registry");
}

/**
 * Module already registered error
 */
inline Error make_module_already_registered_error(const std::string& module_name) {
    return Error::from_code(ErrorCodes::MODULE_ALREADY_REGISTERED,
                            "Module already registered: " + module_name,
                            "module_registry");
}

// ── Global accessors (same pattern as get_file_service/set_file_service) ────
ModuleRegistry* get_module_registry();
void set_module_registry(ModuleRegistry* registry);

} // namespace NoteDaemon

#endif // MODULE_REGISTRY_H
