// include/module_framework/error_collector.h
// Pull-based error collection from modules

#ifndef ERROR_COLLECTOR_H
#define ERROR_COLLECTOR_H

#include <vector>
#include <mutex>
#include "error.h"
#include "imodule.h"

namespace NoteDaemon {

/**
 * Error collector - pulls errors from all registered modules
 * Thread-safe, pull-based design
 */
class ErrorCollector {
public:
    ErrorCollector() = default;
    ~ErrorCollector() = default;
    
    // Prevent copying
    ErrorCollector(const ErrorCollector&) = delete;
    ErrorCollector& operator=(const ErrorCollector&) = delete;

    /**
     * Register a module to collect errors from
     * 
     * @param module Module to register
     */
    void register_module(IModule* module);
    
    /**
     * Unregister a module
     * 
     * @param module Module to unregister
     */
    void unregister_module(IModule* module);
    
    /**
     * Pull errors from all registered modules
     * 
     * @param errors Vector to append errors to (errors from all modules)
     */
    void collect_all(std::vector<Error>& errors) const;
    
    /**
     * Pull errors from all registered modules (returns new vector)
     * 
     * @return Vector of all errors from all modules
     */
    std::vector<Error> collect() const;
    
    /**
     * Get count of registered modules
     * 
     * @return Number of modules
     */
    size_t module_count() const;
    
    /**
     * Clear all registered modules
     */
    void clear();

private:
    mutable std::mutex mutex_;
    std::vector<IModule*> modules_;
};

/**
 * Core error collector - collects errors from core systems
 * Modules can also register with this to be included in global collection
 */
class CoreErrorCollector {
public:
    CoreErrorCollector() = default;
    ~CoreErrorCollector() = default;
    
    // Prevent copying
    CoreErrorCollector(const CoreErrorCollector&) = delete;
    CoreErrorCollector& operator=(const CoreErrorCollector&) = delete;
    
    /**
     * Add a core error (not from a module)
     * 
     * @param error Error to add
     */
    void add_core_error(const Error& error);
    
    /**
     * Add error collector from modules
     * 
     * @param collector Module error collector
     */
    void add_module_collector(ErrorCollector* collector);
    
    /**
     * Collect all errors (core + all module collectors)
     * 
     * @return Vector of all errors
     */
    std::vector<Error> collect_all() const;
    
    /**
     * Clear all errors
     */
    void clear();

private:
    mutable std::mutex mutex_;
    std::vector<Error> core_errors_;
    std::vector<ErrorCollector*> module_collectors_;
};

} // namespace NoteDaemon

#endif // ERROR_COLLECTOR_H