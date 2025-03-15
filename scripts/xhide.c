#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>

// Display usage information
void show_usage(const char *prog_name) {
    fprintf(stderr,
        "XHide - Process Faker\n"
        "Usage: %s [options] <program> [arguments]\n\n"
        "Options:\n"
        "  -s <string>   Fake process name\n"
        "  -d            Run application as daemon\n"
        "  -u <uid[:gid]> Change user and group ID\n"
        "  -p <filename> Save PID to a file\n\n"
        "Example: %s -s \"fake-process\" -d -p fake.pid ./real-program arg1 arg2\n",
        prog_name, prog_name);
    exit(EXIT_FAILURE);
}

// Change user and group ID
int set_user_group(const char *user_group) {
    char user[256] = {0};
    const char *group = NULL;
    struct passwd *pwd;
    struct group *grp;
    uid_t uid;
    gid_t gid;

    // Parse user and group
    strncpy(user, user_group, sizeof(user) - 1);
    group = strchr(user, ':');
    if (group) {
        *strchr(user, ':') = '\0'; // Split user and group
        group++;
    }

    // Resolve UID
    if ((pwd = getpwnam(user)) != NULL) {
        uid = pwd->pw_uid;
        gid = pwd->pw_gid;  // Default group is from passwd
    } else {
        uid = (uid_t) atoi(user);
    }

    // Resolve GID
    if (group) {
        if ((grp = getgrnam(group)) != NULL) {
            gid = grp->gr_gid;
        } else {
            gid = (gid_t) atoi(group);
        }
    }

    // Set GID
    if (setgid(gid)) {
        perror("Error: Unable to set GID");
        return 0;
    }

    // Set UID
    if (setuid(uid)) {
        perror("Error: Unable to set UID");
        return 0;
    }

    return 1;
}

// Get the full path to an executable
char *get_full_path(const char *cmd) {
    char *path_env = getenv("PATH");
    char *path = NULL;
    char *full_path = (char *)malloc(256);
    struct stat st;

    if (!full_path) {
        perror("Memory allocation error");
        return NULL;
    }

    // If the command is an absolute path
    if (cmd[0] == '/') {
        strcpy(full_path, cmd);
        return full_path;
    }

    // If the command is relative to current directory
    if (cmd[0] == '.') {
        if (getcwd(full_path, 255)) {
            strcat(full_path, "/");
            strcat(full_path, cmd);
            return full_path;
        }
        free(full_path);
        return NULL;
    }

    // Search in PATH environment variable
    char *p = strtok(path_env, ":");
    while (p != NULL) {
        snprintf(full_path, 256, "%s/%s", p, cmd);
        if (stat(full_path, &st) == 0 && S_ISREG(st.st_mode) &&
            (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))) {
            return full_path;
        }
        p = strtok(NULL, ":");
    }

    free(full_path);
    return NULL;
}

// Run the process as a daemon
void run_as_daemon() {
    int dev_null = open("/dev/null", O_RDWR);
    if (dev_null == -1) {
        perror("Error: Unable to open /dev/null");
        exit(EXIT_FAILURE);
    }

    if (fork() != 0) {
        exit(EXIT_SUCCESS); // Parent exits
    }

    if (setsid() == -1) {
        perror("Error: Unable to create a new session");
        exit(EXIT_FAILURE);
    }

    if (fork() != 0) {
        exit(EXIT_SUCCESS); // First child exits
    }

    umask(0);
    dup2(dev_null, STDIN_FILENO);
    dup2(dev_null, STDOUT_FILENO);
    dup2(dev_null, STDERR_FILENO);
    close(dev_null);
}

int main(int argc, char **argv) {
    char *fake_name = NULL;
    char *pid_file = NULL;
    int daemon_mode = 0;

    if (argc < 2) {
        show_usage(argv[0]);
    }

    // Parse command-line arguments
    int opt;
    while ((opt = getopt(argc, argv, "s:u:p:d")) != -1) {
        switch (opt) {
            case 's':
                fake_name = optarg;
                break;
            case 'u':
                if (!set_user_group(optarg)) {
                    exit(EXIT_FAILURE);
                }
                break;
            case 'p':
                pid_file = optarg;
                break;
            case 'd':
                daemon_mode = 1;
                break;
            default:
                show_usage(argv[0]);
        }
    }

    // Validate arguments
    if (optind >= argc || !fake_name) {
        show_usage(argv[0]);
    }

    // Resolve full path of the executable
    char *exec_path = get_full_path(argv[optind]);
    if (!exec_path) {
        perror("Error resolving executable path");
        exit(EXIT_FAILURE);
    }

    // Prepare the new argument list
    int new_argc = argc - optind;
    char **new_argv = (char **)malloc((new_argc + 1) * sizeof(char *));
    if (!new_argv) {
        perror("Memory allocation error");
        free(exec_path);
        exit(EXIT_FAILURE);
    }
    new_argv[0] = fake_name; // Set fake process name
    for (int i = 1; i < new_argc; i++) {
        new_argv[i] = argv[optind + i];
    }
    new_argv[new_argc] = NULL;

    // Run as daemon if requested
    if (daemon_mode) {
        run_as_daemon();
    }

    // Save PID to file if requested
    if (pid_file) {
        FILE *f = fopen(pid_file, "w");
        if (f) {
            fprintf(f, "%d\n", getpid());
            fclose(f);
        } else {
            perror("Error writing PID file");
        }
    }

    // Execute the program with the fake name
    execv(exec_path, new_argv);
    perror("Execution failed");
    free(exec_path);
    free(new_argv);
    return EXIT_FAILURE;
}