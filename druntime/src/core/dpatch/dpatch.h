#ifndef DPATCH_H
#define DPATCH_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Call once at startup. Opens the Unix domain socket for patches.
 * sock_path can be NULL for default "/tmp/dpatch-<pid>.sock".
 * Returns 0 on success, negative error code on failure.
 */
int dpatch_init(const char* sock_path);

/*
 * Non-blocking poll for incoming connections and patches.
 * Call this inside your main loop.
 * Returns the number of successfully patched functions, or 0 if none.
 */
int dpatch_poll(void);

/*
 * Blocking wait for the next patch.
 * Returns the number of patched functions on success, or negative error code.
 */
int dpatch_wait(void);

/*
 * Clean up Unix socket and uninstall signal handler.
 */
void dpatch_shutdown(void);

#ifdef __cplusplus
}
#endif

#endif /* DPATCH_H */
