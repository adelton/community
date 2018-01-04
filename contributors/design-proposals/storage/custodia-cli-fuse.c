/*
  FUSE flexVolume which calls custodia-cli get <the-name> and presents
  the output as file contents.
  Author: Jan Pazdziora

  gcc -Wall custodia-cli-fuse.c $( pkg-config fuse json-c --cflags --libs ) \
      -D LOG_FILE=/tmp/custodia-cli.log \
      -o /usr/libexec/kubernetes/kubelet-plugins/volume/exec/example.com~custodia-cli-fuse/custodia-cli-fuse
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <time.h>

#define FUSE_USE_VERSION 29

#include <fuse.h>

#include <json.h>
#include <json_tokener.h>
#include <json_object.h>

#define _QUOTE1(x) #x
#define _QUOTE2(x) _QUOTE1(x)
#ifdef LOG_FILE
#define _LOG_FILE _QUOTE2(LOG_FILE)
#else
#define _LOG_FILE "/dev/null"
#endif

static FILE * log = NULL;

char * file_path = NULL;
unsigned long file_length;
void * file_content = NULL;
time_t file_mtime;

static int custodia_cli_readdir(const char * path, void * dir,
		fuse_fill_dir_t filler,
		off_t offset, struct fuse_file_info * fi) {
	fprintf(log, "custodia_cli_readdir(%s)\n", path); fflush(log);
	if (strcmp(path, "/") != 0) {
		return -ENOENT;
	}
	filler(dir, ".", NULL, 0);
	filler(dir, "..", NULL, 0);
	return 0;
}

#define READ_CHUNK_SIZE 2048
static void * custodia_cli_refresh(const char * path) {
	fprintf(log, "custodia_cli_refresh(%s)\n", path); fflush(log);
	file_mtime = time(NULL);
	char mtime_str[64];
	strftime(mtime_str, sizeof(mtime_str), "%F %T", localtime(&file_mtime));

	int wstatus;
	int stdout_pipe[2];
	ssize_t stdout_length = 0;
	char * stdout_buffer = malloc(READ_CHUNK_SIZE);
	if (stdout_buffer == NULL) {
		return NULL;
	}

	pipe(stdout_pipe);
	if (fork()) {
		fprintf(log, "custodia_cli_refresh forked\n"); fflush(log);
		close(stdout_pipe[1]);
		ssize_t chunk_length;
		while ((chunk_length = read(stdout_pipe[0], stdout_buffer + stdout_length, READ_CHUNK_SIZE)) > 0) {
			fprintf(log, "custodia_cli_refresh read %ld\n", chunk_length); fflush(log);
			stdout_length += chunk_length;
			char * new_stdout_buffer = realloc(stdout_buffer, stdout_length + READ_CHUNK_SIZE);
			if (new_stdout_buffer == NULL) {
				free(stdout_buffer);
				stdout_buffer = NULL;
				break;
			}
			stdout_buffer = new_stdout_buffer;
		}
		fprintf(log, "custodia_cli_refresh length %ld\n", stdout_length); fflush(log);
		close(stdout_pipe[0]);
		wait(&wstatus);
	} else {
		fprintf(log, "custodia_cli_refresh in child\n"); fflush(log);
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		dup2(fileno(log), STDERR_FILENO);
		dup2(stdout_pipe[1], STDOUT_FILENO);
		close(stdout_pipe[0]);
		close(stdout_pipe[1]);

		fprintf(log, "custodia_cli_refresh before exec\n"); fflush(log);

		execlp("custodia-cli", "custodia-cli", "get", path, (char *)NULL);
		fprintf(log, "custodia_cli_refresh execl failed\n"); fflush(log);
		exit(127);
	}

	if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus)) {
		fprintf(log, "custodia_cli_refresh wstatus indicates error\n"); fflush(log);
		if (stdout_buffer) {
			free(stdout_buffer);
		}
		return NULL;
	}

	file_content = stdout_buffer;
	file_mtime = time(NULL);
	file_length = stdout_length;
	file_path = strdup(path);

	return stdout_buffer;
}

static void * custodia_cli_get_content(const char * path) {
	if (path == NULL || path[0] != '/') {
		return NULL;
	}
	if (file_path != NULL && strcmp(path, file_path) != 0) {
		free(file_content);
		free(file_path);
		file_path = NULL;
	}
	if (file_path == NULL) {
		if (custodia_cli_refresh(path) == NULL) {
			return NULL;
		}
	}
	return file_content;
}

static int custodia_cli_open(const char * path, struct fuse_file_info * fi) {
	fprintf(log, "custodia_cli_open(%s)\n", path); fflush(log);
	if ((fi->flags & 3) != O_RDONLY) {
		return -EACCES;
	}
	void * content = custodia_cli_get_content(path);
	if (content == NULL) {
		return -ENOENT;
	}
	return 0;
}

static int custodia_cli_getattr(const char * path, struct stat * stinfo) {
	fprintf(log, "custodia_cli_getattr(%s)\n", path); fflush(log);
	memset(stinfo, 0, sizeof(struct stat));
	if (strcmp(path, "/") == 0 || strcmp(path, "/certs") == 0 || strcmp(path, "/certs/HTTP") == 0) {
		stinfo->st_mode = S_IFDIR | 0755;
		stinfo->st_nlink = 2;
	} else {
		void * content = custodia_cli_get_content(path);
		if (content == NULL) {
			return -ENOENT;
		}
		stinfo->st_mode = S_IFREG | 0444;
		stinfo->st_nlink = 1;
		stinfo->st_size = file_length;
		stinfo->st_mtime = file_mtime;
	}
	return 0;
}

static int custodia_cli_read(const char * path, char * buf,
		size_t size, off_t offset, struct fuse_file_info * fi) {
	fprintf(log, "custodia_cli_read(%s)\n", path); fflush(log);
	void * content = custodia_cli_get_content(path);
	if (content == NULL) {
		return -ENOENT;
	}
	if (offset < file_length) {
		if (offset + size > file_length)
			size = file_length - offset;
		memcpy(buf, file_content + offset, size);
		return size;
	}
	return 0;
}

static struct fuse_operations custodia_cli_operations = {
	.getattr	= custodia_cli_getattr,
	.readdir	= custodia_cli_readdir,
	.open		= custodia_cli_open,
	.read		= custodia_cli_read,
};

int not_supported(const char * msg) {
	printf("{ \"status\": \"Not supported\", \"message\": \"%s\" }\n", msg);
	exit(1);
}

int do_mount(int argc, char * argv[]) {
	if (argc != 4) {
		not_supported("mount expects two additional parameters");
	}

	char * new_argv[] = {
		argv[0],
		"-o", "allow_other",
		argv[2],
		NULL
	};

	int wstatus;
	int stderr_pipe[2];
	char stderr_buffer[1024];
	pipe(stderr_pipe);
	if (fork()) {
		close(stderr_pipe[1]);
		int count = read(stderr_pipe[0], stderr_buffer, sizeof(stderr_buffer) - 1);
		if (count >= 0) {
			stderr_buffer[count] = '\0';
		}
		close(stderr_pipe[0]);
		wait(&wstatus);
	} else {
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
		dup2(stderr_pipe[1], STDERR_FILENO);
		close(stderr_pipe[0]);
		close(stderr_pipe[1]);
		int ret = fuse_main(4, new_argv, &custodia_cli_operations, NULL);
		exit(ret);
	}

	if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus)) {
		json_object * obj;
		obj = json_object_new_string(stderr_buffer);
		printf("%s%s%s\n", "{ \"status\": \"Failure\", \"message\": ",
			json_object_to_json_string(obj),
			" }");
		exit(1);
	}
	puts("{ \"status\": \"Success\" }");
	exit(0);
}

int do_umount(int argc, char * argv[]) {
	if (argc != 3) {
		not_supported("umount expects one additional parameter");
	}
	int wstatus;
	if (fork()) {
		wait(&wstatus);
	} else {
		execl("/usr/bin/umount", "-f",  argv[2], (char *) 0);
		exit(0);
	}

	if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus)) {
		puts("{ \"status\": \"Failure\", \"message\": \"umount failed\" }");
		exit(1);
	}

	unlink(argv[3]);
	puts("{ \"status\": \"Success\" }");
	exit(0);
}

int main(int argc, char * argv[]) {
	log = fopen(_LOG_FILE, "a");
	time_t now = time(NULL);
	char now_str[64];
	strftime(now_str, sizeof(now_str), "%F %T", localtime(&now));
	fputs(now_str, log);
	int i;
	for (i = 1; i < argc; i++) {
		fputs(" ", log);
		fputs(argv[i], log);
	}
	fputs("\n", log);
	// fclose(log);

	if (argc < 2) {
		not_supported("at least one parameter expected");
	}

	if (strcmp(argv[1], "init") == 0) {
		puts("{ \"status\": \"Success\", \"capabilities\": {\"attach\": false, \"selinuxRelabel\": false }}");
		exit(0);
	} else if (strcmp(argv[1], "umount") == 0) {
		do_umount(argc, argv);
	} else if (strcmp(argv[1], "mount") == 0) {
		do_mount(argc, argv);
	}
	not_supported("unknown command");
	exit(2);
}
