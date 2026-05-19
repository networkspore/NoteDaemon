 #ifndef ASYNC_LOGGER_H                                                                                                        
   #define ASYNC_LOGGER_H                                                                                                        
                                                                                                                                 
   #include <string_view>                                                                                                        
   #include <thread>                                                                                                             
   #include <atomic>                                                                                                             
   #include <unistd.h>                                                                                                           
   #include <fcntl.h>                                                                                                            
   #include <cstring>                                                                                                            
   #include <sys/syslog.h>                                                                                                       
                                                                                                                                 
   namespace AsyncLogger {                                                                                                       
                                                                                                                                 
   class Logger {                                                                                                                
   private:                                                                                                                      
       static int pipe_fds_[2];                                                                                                  
       static std::atomic<bool> running_;                                                                                        
       static std::thread logger_thread_;                                                                                        
       static bool initialized_;                                                                                                 
                                                                                                                                 
       static void logger_thread_func() {                                                                                        
           char buf[4096];                                                                                                       
           while (true) {                                                                                                        
               ssize_t n = read(pipe_fds_[0], buf, sizeof(buf) - 1);                                                             
               if (n <= 0) break; // EOF or error                                                                                
               buf[n] = '\0';                                                                                                    
                                                                                                                                 
               char* start = buf;                                                                                                
               char* end = buf + n;                                                                                              
               while (start < end) {                                                                                             
                   char* nl = (char*)std::memchr(start, '\n', end - start);                                                      
                   if (!nl) break;                                                                                               
                   *nl = '\0';                                                                                                   
                   log_line(start);                                                                                              
                   start = nl + 1;                                                                                               
               }                                                                                                                 
           }                                                                                                                     
       }                                                                                                                         
                                                                                                                                 
       static void log_line(const char* line) {                                                                                  
           if (!line || *line == '\0') return;                                                                                   
                                                                                                                                 
           char level_char = line[0];                                                                                            
           const char* p = line + 1;                                                                                             
           while (*p == ' ') p++;                                                                                                
                                                                                                                                 
           const char* sep = std::strstr(p, " | ");                                                                              
           if (!sep) return;                                                                                                     
                                                                                                                                 
           std::string_view component(p, sep - p);                                                                               
           std::string_view message(sep + 3);                                                                                    
                                                                                                                                 
           int priority;                                                                                                         
           switch (level_char) {                                                                                                 
               case 'D': priority = LOG_DEBUG; break;                                                                            
               case 'I': priority = LOG_INFO; break;                                                                             
               case 'W': priority = LOG_WARNING; break;                                                                          
               case 'E': priority = LOG_ERR; break;                                                                              
               case 'C': priority = LOG_CRIT; break;                                                                             
               default:  priority = LOG_INFO; break;                                                                             
           }                                                                                                                     
                                                                                                                                 
           std::string formatted = "[" + std::string(component) + "] " + std::string(message);                                   
           syslog(priority, "%s", formatted.c_str());                                                                            
       }                                                                                                                         
                                                                                                                                 
       static void write_log(char level, std::string_view comp, std::string_view msg) {                                          
           if (!initialized_) return;                                                                                            
           int fd = pipe_fds_[1];                                                                                                
           if (fd < 0) return;                                                                                                   
                                                                                                                                 
           char buf[1024];                                                                                                       
           int i = 0;                                                                                                            
           buf[i++] = level;                                                                                                     
           buf[i++] = ' ';                                                                                                       
                                                                                                                                 
           size_t c_len = comp.size() > 40 ? 40 : comp.size();                                                                   
           std::memcpy(buf + i, comp.data(), c_len);                                                                             
           i += c_len;                                                                                                           
                                                                                                                                 
           buf[i++] = ' ';                                                                                                       
           buf[i++] = '|';                                                                                                       
           buf[i++] = ' ';                                                                                                       
                                                                                                                                 
           size_t m_len = msg.size() > 900 ? 900 : msg.size();                                                                   
           std::memcpy(buf + i, msg.data(), m_len);                                                                              
           i += m_len;                                                                                                           
                                                                                                                                 
           buf[i++] = '\n';                                                                                                      
                                                                                                                                 
           // Non-blocking write; drop if pipe is full (EAGAIN)                                                                  
           ssize_t n = write(fd, buf, i);                                                                                        
           (void)n;                                                                                                              
       }                                                                                                                         
                                                                                                                                 
   public:                                                                                                                       
       static void start() {                                                                                                     
           if (initialized_) return;                                                                                             
                                                                                                                                 
           if (pipe(pipe_fds_) < 0) return;                                                                                      
                                                                                                                                 
           // Non-blocking for both ends                                                                                         
           fcntl(pipe_fds_[0], F_SETFL, O_NONBLOCK);                                                                             
           fcntl(pipe_fds_[1], F_SETFL, O_NONBLOCK);                                                                             
                                                                                                                                 
           running_.store(true);                                                                                                 
           logger_thread_ = std::thread(logger_thread_func);                                                                     
           initialized_ = true;                                                                                                  
       }                                                                                                                         
                                                                                                                                 
       static void stop() {                                                                                                      
           if (!initialized_) return;                                                                                            
                                                                                                                                 
           running_.store(false);                                                                                                
           close(pipe_fds_[1]); // Close write end -> EOF for reader                                                             
           if (logger_thread_.joinable()) {                                                                                      
               logger_thread_.join();                                                                                            
           }                                                                                                                     
           close(pipe_fds_[0]);                                                                                                  
           initialized_ = false;                                                                                                 
       }                                                                                                                         
                                                                                                                                 
       static void log_debug(std::string_view message, std::string_view component = "NoteDaemon") {                              
           write_log('D', component, message);                                                                                   
       }                                                                                                                         
                                                                                                                                 
       static void log_info(std::string_view message, std::string_view component = "NoteDaemon") {                               
           write_log('I', component, message);                                                                                   
       }                                                                                                                         
                                                                                                                                 
       static void log_warning(std::string_view message, std::string_view component = "NoteDaemon") {                            
           write_log('W', component, message);                                                                                   
       }                                                                                                                         
                                                                                                                                 
       static void log_error(std::string_view message, std::string_view component = "NoteDaemon") {                              
           write_log('E', component, message);                                                                                   
       }                                                                                                                         
                                                                                                                                 
       static void log_critical(std::string_view message, std::string_view component = "NoteDaemon") {                           
           write_log('C', component, message);                                                                                   
       }                                                                                                                         
   };                                                                                                                            
                                                                                                                                 
   // Static definitions                                                                                                         
   inline int AsyncLogger::Logger::pipe_fds_[2] = {-1, -1};                                                                      
   inline std::atomic<bool> AsyncLogger::Logger::running_(false);                                                                
   inline std::thread AsyncLogger::Logger::logger_thread_;                                                                       
   inline bool AsyncLogger::Logger::initialized_(false);                                                                         
                                                                                                                                 
   // Convenience macros                                                                                                         
   #define ASYNC_LOG_DEBUG(msg) AsyncLogger::Logger::log_debug(msg)                                                              
   #define ASYNC_LOG_INFO(msg) AsyncLogger::Logger::log_info(msg)                                                                
   #define ASYNC_LOG_WARNING(msg) AsyncLogger::Logger::log_warning(msg)                                                          
   #define ASYNC_LOG_ERROR(msg) AsyncLogger::Logger::log_error(msg)                                                              
   #define ASYNC_LOG_CRITICAL(msg) AsyncLogger::Logger::log_critical(msg)                                                        
                                                                                                                                 
   #define ASYNC_LOG_DEBUG_COMP(msg, comp) AsyncLogger::Logger::log_debug(msg, comp)                                             
   #define ASYNC_LOG_INFO_COMP(msg, comp) AsyncLogger::Logger::log_info(msg, comp)                                               
   #define ASYNC_LOG_WARNING_COMP(msg, comp) AsyncLogger::Logger::log_warning(msg, comp)                                         
   #define ASYNC_LOG_ERROR_COMP(msg, comp) AsyncLogger::Logger::log_error(msg, comp)                                             
                                                                                                                                 
   } // namespace AsyncLogger                                                                                                    
                                                                                                                                 
   #endif // ASYNC_LOGGER_H  