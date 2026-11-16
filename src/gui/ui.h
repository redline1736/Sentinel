#ifndef UI_H
#define UI_H

/* Runs the SDL3 GUI in the calling process. Blocks until the window
 * closes. If argc >= 4 and argv looks like <outdir> <mode> <target>
 * [flags], the form is prefilled and the scan auto-starts.
 *
 * argv[0] is ignored (the binary's own path is resolved via
 * /proc/self/exe). Returns 0 on success, non-zero on init failure. */
int ui_run(int argc, char **argv);

#endif