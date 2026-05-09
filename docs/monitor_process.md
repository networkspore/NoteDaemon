Exactly. A separate process that:

    Watches the main process via its PID
    Does the LibUSB cleanup when the main process dies for any reason, including SIGKILL

The simplest implementation is just polling:
cpp

// monitor.cpp
int main(int argc, char* argv[]) {
    pid_t watched_pid = atoi(argv[1]);
    
    while (true) {
        if (kill(watched_pid, 0) != 0) {
            // Process is gone — do cleanup
            releaseAllHeldDevices("usb_held_devices.txt");
            break;
        }
        usleep(100000);  // poll every 100ms
    }
}

And your main app launches it on startup:
cpp

int main() {
    pid_t monitor_pid = fork();
    if (monitor_pid == 0) {
        // Child — exec the monitor
        char pid_str[32];
        snprintf(pid_str, sizeof(pid_str), "%d", getppid());
        execl("./monitor", "./monitor", pid_str, nullptr);
    }
    
    // Parent — continue normal execution
}

More Robust Alternatives to kill(pid, 0) Polling

On Linux you can do this without polling at all:
cpp

// Use pidfd — fires immediately when process dies, no polling
int pidfd = pidfd_open(watched_pid, 0);
struct pollfd pfd = { pidfd, POLLIN, 0 };
poll(&pfd, 1, -1);  // blocks until process dies
// cleanup here

Or on Linux you can use prctl in the main process to make the monitor get a signal when the parent dies:
cpp

// In the child/monitor process
prctl(PR_SET_PDEATHSIG, SIGTERM);  // get SIGTERM if parent dies

One Catch

You need to make sure the monitor itself doesn't get killed — so don't put it in the same process group, otherwise a kill -9 <pgid> takes both out simultaneously:
cpp

if (monitor_pid == 0) {
    setsid();  // new session — detaches from parent's process group
    execl("./monitor", "./monitor", pid_str, nullptr);
}

This is essentially the same pattern that systemd, Docker, and most process supervisors use under the hood.

