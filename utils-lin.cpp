/**
 * Operating Sytems 2013 - Assignment 1
 * Florea Stefan - Razvan
 * 331CB
 */

#include <assert.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>

#include "utils.h"

#include <iostream>

using namespace std;

#define READ		0
#define WRITE		1

/**
 * Internal change-directory command.
 */
static bool shell_cd(word_t *dir)
{
	int result;
	
	result = chdir(dir->string);

	if(result < 0)
	{
		fprintf(stderr, "cd: %s: No such file or directory\n", dir->string);
		return false;
	}

	return true;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit()
{
	/* execute exit/quit */
	exit(EXIT_SUCCESS);

	return EXIT_SUCCESS;
}

/**
 * Concatenate parts of the word to obtain the command
 */
static char *get_word(word_t *s)
{
	int string_length = 0;
	int substring_length = 0;

	char *string = NULL;
	char *substring = NULL;

	while (s != NULL) {
		substring = strdup(s->string);

		if (substring == NULL) {
			return NULL;
		}

		if (s->expand == true) {
			char *aux = substring;
			substring = getenv(substring);

			/* prevents strlen from failing */
			if (substring == NULL) {
				substring = (char*)calloc(1, sizeof(char));
				if (substring == NULL) {
					free(aux);
					return NULL;
				}
			}

			free(aux);
		}

		substring_length = strlen(substring);

		string = (char*)realloc(string, string_length + substring_length + 1);
		if (string == NULL) {
			if (substring != NULL)
				free(substring);
			return NULL;
		}

		memset(string + string_length, 0, substring_length + 1);

		strcat(string, substring);
		string_length += substring_length;

		if (s->expand == false) {
			free(substring);
		}

		s = s->next_part;
	}

	return string;
}

/**
 * Concatenate command arguments in a NULL terminated list in order to pass
 * them directly to execv.
 */
static char **get_argv(simple_command_t *command, int *size)
{
	char **argv;
	word_t *param;

	int argc = 0;
	argv = (char**)calloc(argc + 1, sizeof(char *));
	assert(argv != NULL);

	argv[argc] = get_word(command->verb);
	assert(argv[argc] != NULL);

	argc++;

	param = command->params;
	while (param != NULL) {
		argv = (char**)realloc(argv, (argc + 1) * sizeof(char *));
		assert(argv != NULL);

		argv[argc] = get_word(param);
		assert(argv[argc] != NULL);

		param = param->next_word;
		argc++;
	}

	argv = (char**)realloc(argv, (argc + 1) * sizeof(char *));
	assert(argv != NULL);

	argv[argc] = NULL;
	*size = argc;

	return argv;
}

/**
 * Function that verifies if the tree has redirection, and if it
 * has then we treat it adequate.
 */
static int redirect(simple_command_t *s)
{
	int status, result;
	//input redirection
	if(s->in)
	{
		int in = open(s->in->string, O_RDWR, 0644);
		if(in < 0)
		{
			fprintf(stderr,"Error opening file: %s\n", s->in->string);
			return -1;
		}
		dup2(in, STDIN_FILENO);
		result = close(in);
		if(result < 0)	
		{
			fprintf(stderr,"Error closing file: %s\n", s->in->string);
			return -1;	
		}
	}
	//output redirection
	if(s->out)
	{
		char *out_file = get_word(s->out);
		int out, err;
		if(s->io_flags == IO_OUT_APPEND)
			out = open(out_file, O_RDWR | O_CREAT | O_APPEND, 0644);
		else
			out = open(out_file, O_RDWR | O_CREAT | O_TRUNC, 0644);
		free(out_file);
		if(out < 0)
		{
			fprintf(stderr,"Error opening file: %s\n", s->out->string);
			return -1;
		}
		dup2(out, STDOUT_FILENO);
		//error redirection in output redirection
		if(s->err)
		{
			if(strcmp(s->err->string, s->out->string) != 0)
			{
				if(s->io_flags == IO_ERR_APPEND)
					err = open(s->err->string, O_RDWR | O_CREAT | O_APPEND, 0644);
				else
					err = open(s->err->string, O_RDWR | O_CREAT | O_TRUNC, 0644);
				dup2(err, STDERR_FILENO);
			}
			else
				dup2(out, STDERR_FILENO);
		}
		result = close(out);
		if(result < 0)	
		{
			fprintf(stderr,"Error closing file: %s\n", s->out->string);
			return -1;	
		}
	}
	//error redirection
	else if(s->err)
	{
		int err;
		if(s->io_flags == IO_ERR_APPEND)
			err = open(s->err->string, O_RDWR | O_CREAT | O_APPEND, 0644);
		else
			err = open(s->err->string, O_RDWR | O_CREAT | O_TRUNC, 0644);
		if(err < 0)
		{
			fprintf(stderr,"Error opening file: %s\n", s->err->string);
			status = -1;
		}
		dup2(err, STDERR_FILENO);
		result = close(err);
		if(result < 0)	
		{
			fprintf(stderr,"Error closing file: %s\n", s->err->string);
			return -1;	
		}
	}
	return 0;
}

/**
 * Function that verifies if the command is a environment variable
 * assignement.
 */
bool is_env_var(word_t* command)
{
	if(command->next_part != NULL && strcmp(command->next_part->string, "=") == 0)
		return true;
	return false;
}

/**
 * Function that receive a environment variable
 * assignement as input and parse it.
 * It returns an array with the words from command.
 */
char** get_argv_env_var(word_t* command, int *size)
{
	char **argv;
	word_t *arg;

	*size = 0;
	argv = (char**)calloc(*size + 1, sizeof(char*));
	assert(argv != NULL);

	argv[*size] = (char*)command->string;
	assert(argv[*size] != NULL);
	(*size)++;

	arg = command->next_part;	
	while(arg)
	{
		if(strcmp(arg->string, "=") != 0)
		{
			argv = (char**)realloc(argv, (*size + 1) * sizeof(char*));
			assert(argv != NULL);

			argv[*size] = (char*)arg->string;
			assert(argv[*size] != NULL);
			(*size) ++;
		}
		arg = arg->next_part;
	}

	return argv;
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	int status, size;
	pid_t pid;
	char* cmd;
	char** argv;

	/* if builtin command, execute the command */
	if(strcmp(s->verb->string, "cd") == 0)
	{
		int in_temp_fd = dup(0);
		int out_temp_fd = dup(1);
		int err_temp_fd = dup(2);

		status = redirect(s);

		if(s->params)
			status = shell_cd(s->params);

		dup2(in_temp_fd, 0);
		dup2(out_temp_fd, 1);
		dup2(err_temp_fd, 2);
	}

	/* if variable assignment, execute the assignment and return
         * the exit status */
	else if(is_env_var(s->verb))
	{
		argv = get_argv_env_var(s->verb, &size);
		if(size != 2)
			status = -1;
		else
		{
			status = setenv(argv[0], argv[1], 1);
		}
		free(argv);
	}
	else if(strcmp(s->verb->string, "exit") == 0
		|| strcmp(s->verb->string, "quit") == 0)
	{
		status = shell_exit();
	}
	else
	{
	/* if external command:
    *   1. fork new process
	 *     2c. perform redirections in child
    *     3c. load executable in child
    *   2. wait for child
    *   3. return exit status
	 */

		cmd = get_word(s->verb);
		argv = get_argv(s, &size);

		pid = fork();
		if(pid == -1)
			status = EXIT_FAILURE;
		if(pid == 0)
		{
			status = redirect(s);
			if(status >= 0)
			{
				status = execvp(cmd, argv);
				if(status < 0)
				{
					fprintf(stdout,"Execution failed for '%s'\n", cmd);
					free(cmd);
					free(argv);
					exit(EXIT_FAILURE);
				}
			}
		}
		else
		{
			waitpid(pid, &status, 0);
		}

		free(cmd);
		free(argv);
	}

	return status;
}

/**
 * Function that parse a command that comes from a pipe or parallel
 * command.
 */
int parse_parallel_or_pipe(simple_command_t *s, int level, command_t *father)
{
	int size, status = 0;
	char *cmd;
	char **argv;
	cmd = get_word(s->verb);
	argv = get_argv(s, &size);
	status = redirect(s);
	if(status >= 0)
	{
		status = execvp(cmd, argv);
		if(status < 0)
		{
			fprintf(stdout,"Execution failed for '%s'\n", cmd);
			free(cmd);
			free(argv);
			exit(EXIT_FAILURE);
		}
	}
	free(cmd);
	free(argv);

	return status;
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool do_in_parallel(command_t *cmd1, command_t *cmd2, int level, command_t *father)
{
	/* execute cmd1 and cmd2 simultaneously */
	pid_t pid_cmd1, pid_cmd2;
	int status;

	//make first child to execute first command
	pid_cmd1 = fork();
	if(pid_cmd1 == -1)
		return EXIT_FAILURE;
	else if(pid_cmd1 == 0)
		parse_command(cmd1, level, father);
	else
	{
		//make second child to execute second command
		pid_cmd2 = fork();
		if(pid_cmd2 == -1)
			return EXIT_FAILURE;
		else if(pid_cmd2 == 0)
			parse_command(cmd2, level, father);
		else
			waitpid(pid_cmd2, &status, 0);
		waitpid(pid_cmd1, &status, 0);
	}

	return status;
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2)
 */
static bool do_on_pipe(command_t *cmd1, command_t *cmd2, int level, command_t *father)
{
	/* redirect the output of cmd1 to the input of cmd2 */

	pid_t pid_cmd1, pid_cmd2;
	int status;

	/* make first child whose output will be the input of the 
	 * second */
	pid_cmd1 = fork();
	if(pid_cmd1 == -1)
		return EXIT_FAILURE;
	else if(pid_cmd1 == 0)
	{
		int fd[2];
		// create pipe
		pipe (fd);
		/* create second child with the input from the first child
		 * output*/
		pid_cmd2 = fork();
		if(pid_cmd2 == -1)
			return EXIT_FAILURE;
		else if(pid_cmd2 == 0)
		{
			close(fd[0]);
			dup2(fd[1], STDOUT_FILENO);
			close(fd[1]);
			status = parse_command(cmd1, level, father);
			exit(0);
		}
		else
		{	
			close(fd[1]);
			dup2(fd[0], STDIN_FILENO);
			close(fd[0]);	
			status = parse_command(cmd2, level, father);
			exit(0);
		}
	}
	else
	{
			waitpid(pid_cmd2, &status, 0);
			waitpid(pid_cmd1, &status, 0);
	}
	return status;
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	int result, status;
	if (c->op == OP_NONE) {
		/*execute a simple command */
		if(c->up != NULL && (c->up->op == OP_PARALLEL || c->up->op == OP_PIPE))
			status = parse_parallel_or_pipe(c->scmd, level, father);
		else
			status =  parse_simple(c->scmd, level, father);

		return status;
	}

	switch (c->op) {
	case OP_SEQUENTIAL:
		/* execute the commands one after the other */
		status = parse_command(c->cmd1, level, father);
		status = parse_command(c->cmd2, level, father);
		break;

	case OP_PARALLEL:
		/* execute the commands simultaneously */
		status = do_in_parallel(c->cmd1, c->cmd2, level, c);
		break;

	case OP_CONDITIONAL_NZERO:
		/* execute the second command only if the first one
                 * returns non zero */
		status = parse_command(c->cmd1, level, father);
		if(status != 0)
			status = parse_command(c->cmd2, level, father);
		break;

	case OP_CONDITIONAL_ZERO:
		/* execute the second command only if the first one
                 * returns zero */
		status = parse_command(c->cmd1, level, father);
		if(status == 0)
			status = parse_command(c->cmd2, level, father);
		break;

	case OP_PIPE:
		/* redirect the output of the first command to the
		 * input of the second */
		status = do_on_pipe(c->cmd1, c->cmd2, level, father);
		break;

	default:
		assert(false);
	}

	return status; /* replace with actual exit code of command */
}

/**
 * Readline from mini-shell.
 */
char *read_line()
{
	char *instr;
	char *chunk;
	char *ret;

	int instr_length;
	int chunk_length;

	int endline = 0;

	instr = NULL;
	instr_length = 0;

	chunk = (char*)calloc(CHUNK_SIZE, sizeof(char));
	if (chunk == NULL) {
		fprintf(stderr, ERR_ALLOCATION);
		return instr;
	}

	while (!endline) {
		ret = fgets(chunk, CHUNK_SIZE, stdin);
		if (ret == NULL) {
			break;
		}

		chunk_length = strlen(chunk);
		if (chunk[chunk_length - 1] == '\n') {
			chunk[chunk_length - 1] = 0;
			endline = 1;
		}

		ret = instr;
		instr = (char*)realloc(instr, instr_length + CHUNK_SIZE + 1);
		if (instr == NULL) {
			free(ret);
			return instr;
		}
		memset(instr + instr_length, 0, CHUNK_SIZE);
		strcat(instr, chunk);
		instr_length += chunk_length;
	}

	free(chunk);

	return instr;
}

