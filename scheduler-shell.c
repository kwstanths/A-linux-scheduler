#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <assert.h>

#include <sys/wait.h>
#include <sys/types.h>

#include "proc-common.h"
#include "request.h"

/* Compile-time parameters. */
#define SCHED_TQ_SEC 5               /* time quantum */
#define TASK_NAME_SZ 60               /* maximum size for a task's name */
#define SHELL_EXECUTABLE_NAME "shell" /* executable for shell */

struct process {

    int number;
    pid_t pid;
    char * name;
    int prio;
    struct process * nextProcess;
};
struct process * processList = NULL;
struct process * RoundRobin;
int nproc;

struct process * addProcessToList(struct process * List,int number, pid_t pid,char * name,int prio){

    struct process * temp;
    temp = (struct process *)malloc(sizeof(struct process));
    if (temp == NULL){
        printf("Out of memory...\n");
        exit(1);
    }

    temp->number = number;
    temp->pid = pid;
    temp->name = (char *)malloc(strlen(name)*sizeof(char) + 1);
    if (temp->name == NULL){
        printf("Out of memory...\n");
        exit(1);
    }
    temp->prio = prio;
    strcpy(temp->name,name);
    temp->nextProcess = List;

    return temp;
}

struct process * deleteProcessFromList(struct process * List, pid_t pid){

    struct process * current, * previous;
    current = List;

    if(List == NULL){
        printf("I can not find shit in an empty list...\n");
        exit(1);
    }

    if(current->pid == pid){
        previous = current;
        current = current->nextProcess;
        free(previous->name);
        free(previous);
        return current;
    }
    previous = current;
    current = current->nextProcess;
    while(current != NULL){
        if (current->pid == pid){
            previous->nextProcess=current->nextProcess;
            free(current->name);
            free(current);
            return List;
        }
        previous = current;
        current = current->nextProcess;
    }

    printf("I did not find the reqested node with %ld PID.\n",(long)pid);
    exit(1);
}

struct process * insert_low_process(struct process * List, int number, pid_t pid, char * name){

    struct process * current;
    struct process * previous;

    struct process * temp;
    temp = (struct process *)malloc(sizeof(struct process));
    if (temp == NULL){
        printf("Out of memory...\n");
        exit(1);
    }

    temp->number = number;
    temp->pid = pid;
    temp->name = (char *)malloc(strlen(name)*sizeof(char) + 1);
    if (temp->name == NULL){
        printf("Out of memory...\n");
        exit(1);
    }
    temp->prio = 0;
    strcpy(temp->name,name);

    current = List;
    if (current == NULL){
        temp->nextProcess = NULL;
        return temp;
    } else if (current->prio == 0){
        temp->nextProcess = List;
        return temp;
    } else{
        previous = current;
        current = current->nextProcess;
        while(current != NULL && current->prio == 1){
            previous = current;
            current = current->nextProcess;
        }

        previous->nextProcess = temp;
        temp->nextProcess = current;

        return List;
    }

}

struct process * find_process_given_the_ID(struct process * List,int ID){

    struct process * temp = List;
    while(temp != NULL){
        if (temp->number == ID){
            return temp;
        }
        temp = temp->nextProcess;
    }
    return NULL;

}


/* Print a list of all tasks currently being scheduled.  */
static void
sched_print_tasks(void)
{
	struct process * temp = processList;

    while(temp != NULL) {
        printf("Process: %s\n\tPID: %ld\n\tNumber: %d",temp->name,(long)temp->pid,temp->number);
        if (temp->number == RoundRobin->number){
            printf("\t\t\t<-------------RUNNING\n\t");
        }
        if (temp->prio == 0){
            printf("\nPriority: LOW\n");
            }
        else{
            printf("\nPriority: HIGH\n");
        }
        temp = temp->nextProcess;
    }
    return;
}

/* Send SIGKILL to a task determined by the value of its
 * scheduler-specific id.
 */
static int
sched_kill_task_by_id(int id)
{
    struct process * process_to_kill;
    process_to_kill = find_process_given_the_ID(processList,id);
    printf("I am going to delete process %d!!!\n",process_to_kill->pid);
    if (process_to_kill == NULL){
        printf("There is no processs with the given number.\n");
        return -ENOSYS;
    }
    kill(process_to_kill->pid,SIGKILL);
    return process_to_kill->pid;
}


/* Create a new task.  */
static void
sched_create_task(char *executable)
{
    char *newargv[] = { NULL, NULL, NULL, NULL };
    char *newenviron[] = { NULL };
    pid_t newPID;

    newPID = fork();
    if (newPID<0){
        perror("fork");
        exit(1);
    }
     if (newPID == 0){
        raise(SIGSTOP);
        newargv[0] = executable;
        execve(executable, newargv, newenviron);
        perror("execve");
        exit(1);
    }
    wait_for_ready_children(1);
    processList = insert_low_process(processList,nproc,newPID,executable);
    nproc++;
}

static void
change_prio_to_high(int id)
{


    struct process * current;
    struct process * previous;


    current = processList;
    if (current == NULL){
        printf("Internal error. Trying to change priority in an empty list!!!\n");
        return;
    }else if(current->number == id){
        current->prio = 1;
    } else {
        previous = current;
        current = current->nextProcess;

        while(current != NULL && current->number != id){
           previous = current;
           current = current->nextProcess;
        }

        if (current == NULL){
            printf("There is no process with number: %d\n",id);
            return;
        }else{
            current->prio = 1;
            previous->nextProcess = current->nextProcess;
            current->nextProcess = processList;
            processList = current;
            return;
        }


    }


}


struct process * remove_high_from_list(struct process * List,int id){
    struct process * temp = List;
    struct process * current;
    struct process * previous;

    if (temp ==NULL){
        printf("Internal error. Trying to change priority in an empty list!!!\n");
        return NULL;
    }
    if (temp->number == id){
        processList = temp->nextProcess;
        return temp;
    }

    current = temp->nextProcess;
    previous = temp;
    while(current!=NULL && current->number!=id){
        previous = current;
        current = current->nextProcess;
    }

    if (current == NULL){
        return NULL;
    }
    if (current->prio == 1){
        previous->nextProcess = current->nextProcess;
        return current;
    }
    return current;
}



static void change_prio_to_low(int id){
       struct process * process_to_change_priority;
       struct process * previous;
       struct process * current;


       process_to_change_priority = remove_high_from_list(processList,id);

       if (process_to_change_priority != NULL && process_to_change_priority->prio != 0){
            process_to_change_priority->prio = 0;

            current = processList;
            if (current->prio == 0){
                process_to_change_priority->nextProcess = current;
                processList = process_to_change_priority;
                return;
            }
            previous = current;
            current = current->nextProcess;
            while(current != NULL && current->prio == 1){
                previous = current;
                current = current->nextProcess;
            }

            previous->nextProcess = process_to_change_priority;
            process_to_change_priority->nextProcess = current;
            return;
       }


}




/* Process requests by the shell.  */
static int
process_request(struct request_struct *rq)
{
	switch (rq->request_no) {
		case REQ_PRINT_TASKS:
			sched_print_tasks();
			return 0;

		case REQ_KILL_TASK:
			return sched_kill_task_by_id(rq->task_arg);

		case REQ_EXEC_TASK:
			sched_create_task(rq->exec_task_arg);
			return 0;

        case REQ_HIGH_TASK:
            change_prio_to_high(rq->task_arg);
            return 0;

        case REQ_LOW_TASK:
            change_prio_to_low(rq->task_arg);
            return 0;

		default:
			return -ENOSYS;
	}
}

/*
 * SIGALRM handler
 */
static void
sigalrm_handler(int signum)
{
	if (signum != SIGALRM) {
		fprintf(stderr, "Internal error: Called for signum %d, not SIGALRM\n",
			signum);
		exit(1);
	}

	printf("ALARM! %d seconds have passed.\n", SCHED_TQ_SEC);
	printf("Stopping the process with name: %s and PID: %ld and number: %d\n",RoundRobin->name,(long)RoundRobin->pid,RoundRobin->number);
    kill(RoundRobin->pid,SIGSTOP);
}

/*
 * SIGCHLD handler
 */
static void
sigchld_handler(int signum)
{
	 pid_t p;
	int status;

	if (signum != SIGCHLD) {
		fprintf(stderr, "Internal error: Called for signum %d, not SIGCHLD\n",
			signum);
		exit(1);
	}

	/*
	 * Something has happened to one of the children.
	 * We use waitpid() with the WUNTRACED flag, instead of wait(), because
	 * SIGCHLD may have been received for a stopped, not dead child.
	 *
	 * A single SIGCHLD may be received if many processes die at the same time.
	 * We use waitpid() with the WNOHANG flag in a loop, to make sure all
	 * children are taken care of before leaving the handler.
	 */

	for (;;) {
		p = waitpid(-1, &status, WUNTRACED | WNOHANG);
		if (p < 0) {
			perror("waitpid");
			exit(1);
		}
		if (p == 0)
			break;

		explain_wait_status(p, status);


		if (WIFEXITED(status) || WIFSIGNALED(status)) {
			/* A child has died */
            processList = deleteProcessFromList(processList,p);

            if (processList == NULL){
                printf("All processes have terminated. There is nothing left to do...\n");
                exit(0);
            }
            if (processList->prio == 1){
                //printf("EDW\n");
                if (RoundRobin->prio == 0) RoundRobin = processList;
                else if (RoundRobin->nextProcess == NULL) RoundRobin = processList;
                else if ((RoundRobin->nextProcess)->prio == 0) RoundRobin = processList;
                else RoundRobin = RoundRobin->nextProcess;
            }else {
                //printf("KAI EDW\n");
                if (RoundRobin->nextProcess == NULL) RoundRobin = processList;
                else RoundRobin = RoundRobin->nextProcess;
            }

            //sched_print_tasks();


            printf("Weaking up the process with name: %s and PID: %ld and number: %d\n",RoundRobin->name,(long)RoundRobin->pid,RoundRobin->number);

            if (alarm(SCHED_TQ_SEC) < 0) {
                perror("alarm");
                exit(1);
            }

            kill(RoundRobin->pid,SIGCONT);


		}
		if (WIFSTOPPED(status)) {
			/* A child has stopped due to SIGSTOP/SIGTSTP, etc... */
			printf("Parent: Child has been stopped. Moving right along...\n");


            if (processList->prio == 1){
                //printf("STOPPED EDW\n");
                if (RoundRobin->prio == 0) RoundRobin = processList;
                else if (RoundRobin->nextProcess == NULL) RoundRobin = processList;
                else if ((RoundRobin->nextProcess)->prio == 0) RoundRobin = processList;
                else RoundRobin = RoundRobin->nextProcess;
            }else {
                //printf("STOPPED KAI EDW\n");
                if (RoundRobin->nextProcess == NULL) RoundRobin = processList;
                else RoundRobin = RoundRobin->nextProcess;
            }

            printf("Weaking up the process with name: %s and PID: %ld and number: %d\n",RoundRobin->name,(long)RoundRobin->pid,RoundRobin->number);
            //sched_print_tasks();
            if (alarm(SCHED_TQ_SEC) < 0) {
                perror("alarm");
                exit(1);
            }

            kill(RoundRobin->pid,SIGCONT);

		}
	}
}

/* Disable delivery of SIGALRM and SIGCHLD. */
static void
signals_disable(void)
{
	sigset_t sigset;

	sigemptyset(&sigset);
	sigaddset(&sigset, SIGALRM);
	sigaddset(&sigset, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &sigset, NULL) < 0) {
		perror("signals_disable: sigprocmask");
		exit(1);
	}
}

/* Enable delivery of SIGALRM and SIGCHLD.  */
static void
signals_enable(void)
{
	sigset_t sigset;

	sigemptyset(&sigset);
	sigaddset(&sigset, SIGALRM);
	sigaddset(&sigset, SIGCHLD);
	if (sigprocmask(SIG_UNBLOCK, &sigset, NULL) < 0) {
		perror("signals_enable: sigprocmask");
		exit(1);
	}
}


/* Install two signal handlers.
 * One for SIGCHLD, one for SIGALRM.
 * Make sure both signals are masked when one of them is running.
 */
static void
install_signal_handlers(void)
{
	sigset_t sigset;
	struct sigaction sa;

	sa.sa_handler = sigchld_handler;
	sa.sa_flags = SA_RESTART;
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGCHLD);
	sigaddset(&sigset, SIGALRM);
	sa.sa_mask = sigset;
	if (sigaction(SIGCHLD, &sa, NULL) < 0) {
		perror("sigaction: sigchld");
		exit(1);
	}

	sa.sa_handler = sigalrm_handler;
	if (sigaction(SIGALRM, &sa, NULL) < 0) {
		perror("sigaction: sigalrm");
		exit(1);
	}

	/*
	 * Ignore SIGPIPE, so that write()s to pipes
	 * with no reader do not result in us being killed,
	 * and write() returns EPIPE instead.
	 */
	if (signal(SIGPIPE, SIG_IGN) < 0) {
		perror("signal: sigpipe");
		exit(1);
	}
}

static void
do_shell(char *executable, int wfd, int rfd)
{
	char arg1[10], arg2[10];
	char *newargv[] = { executable, NULL, NULL, NULL };
	char *newenviron[] = { NULL };

	sprintf(arg1, "%05d", wfd);
	sprintf(arg2, "%05d", rfd);
	newargv[1] = arg1;
	newargv[2] = arg2;

	raise(SIGSTOP);
	execve(executable, newargv, newenviron);

	/* execve() only returns on error */
	perror("scheduler: child: execve");
	exit(1);
}

/* Create a new shell task.
 *
 * The shell gets special treatment:
 * two pipes are created for communication and passed
 * as command-line arguments to the executable.
 */
static void
sched_create_shell(char *executable, int *request_fd, int *return_fd, pid_t *shell_pid)
{
	pid_t p;
	int pfds_rq[2], pfds_ret[2];

	if (pipe(pfds_rq) < 0 || pipe(pfds_ret) < 0) {
		perror("pipe");
		exit(1);
	}

	p = fork();
	if (p < 0) {
		perror("scheduler: fork");
		exit(1);
	}

	if (p == 0) {
		/* Child */
		close(pfds_rq[0]);
		close(pfds_ret[1]);
		do_shell(executable, pfds_rq[1], pfds_ret[0]);
		assert(0);
	}
	/* Parent */
	close(pfds_rq[1]);
	close(pfds_ret[0]);
	*request_fd = pfds_rq[0];
	*return_fd = pfds_ret[1];
	*shell_pid = p;
}

static void
shell_request_loop(int request_fd, int return_fd)
{
	int ret;
	struct request_struct rq;

	/*
	 * Keep receiving requests from the shell.
	 */
	for (;;) {
		if (read(request_fd, &rq, sizeof(rq)) != sizeof(rq)) {
			perror("scheduler: read from shell");
			fprintf(stderr, "Scheduler: giving up on shell request processing.\n");
			break;
		}
        //printf("MHNYMA");
		signals_disable();
		ret = process_request(&rq);
		signals_enable();

		if (write(return_fd, &ret, sizeof(ret)) != sizeof(ret)) {
			perror("scheduler: write to shell");
			fprintf(stderr, "Scheduler: giving up on shell request processing.\n");
			break;
		}
	}
}

void printList(struct process * List){

    struct process * temp = List;

    while(temp != NULL) {
        printf("Process: %s\n\tPID: %ld\n\tNumber: %d\n\tPriority:",temp->name,(long)temp->pid,temp->number);
        if (temp->prio == 0){
            printf("Low\n\n");
        }else printf("High\n\n");

        temp = temp->nextProcess;
    }
    return;
}

int main(int argc, char *argv[])
{
	int i;
	pid_t shell_pid,temp;
	char *newargv[] = { NULL, NULL, NULL, NULL };
    char *newenviron[] = { NULL };
	/* Two file descriptors for communication with the shell */
	static int request_fd, return_fd;

	/* Create the shell. */
	sched_create_shell(SHELL_EXECUTABLE_NAME, &request_fd, &return_fd, &shell_pid);
	/* TODO: add the shell to the scheduler's tasks */
    processList = addProcessToList(processList,0,shell_pid,SHELL_EXECUTABLE_NAME,0);
	/*
	 * For each of argv[1] to argv[argc - 1],
	 * create a new child process, add it to the process list.
	 */

    for(i=1; i<argc; i++){
        temp = fork();
        if (temp < 0){
            perror("fork");
            exit(1);
        }
        if (temp == 0){
            raise(SIGSTOP);
            newargv[0] = argv[i];
            execve(argv[i], newargv, newenviron);

            perror("execve");
            exit(1);
        }

        processList = addProcessToList(processList,i,temp,argv[i],0);


    }
    printList(processList);
	nproc = argc; /* number of proccesses goes here */
	printf("%d nproc\n",nproc);
	/* Wait for all children to raise SIGSTOP before exec()ing. */
	wait_for_ready_children(nproc);

	/* Install SIGALRM and SIGCHLD handlers. */
	install_signal_handlers();

	if (nproc == 0) {
		fprintf(stderr, "Scheduler: No tasks. Exiting...\n");
		exit(1);
	}

    if (alarm(SCHED_TQ_SEC) < 0) {
		perror("alarm");
		exit(1);
	}

    RoundRobin = processList;
    kill(RoundRobin->pid,SIGCONT);

	shell_request_loop(request_fd, return_fd);

	/* Now that the shell is gone, just loop forever
	 * until we exit from inside a signal handler.
	 */
	while (pause())
		;

	/* Unreachable */
	fprintf(stderr, "Internal error: Reached unreachable point\n");
	return 1;
}
