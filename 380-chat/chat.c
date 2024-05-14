#include <gtk/gtk.h>
#include <glib/gunicode.h> /* for utf8 strlen */
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <getopt.h>
#include "dh.h"
#include "keys.h"
#include <gmp.h>
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

static GtkTextBuffer* tbuf; /* transcript buffer */
static GtkTextBuffer* mbuf; /* message buffer */
static GtkTextView*  tview; /* view for transcript */
static GtkTextMark*   mark; /* used for scrolling to end of transcript, etc */

static pthread_t trecv;     /* wait for incoming messagess and post to queue */

void* recvMsg(void*);       /* for trecv */

#define max(a, b)         \
	({ typeof(a) _a = a;    \
	 typeof(b) _b = b;    \
	 _a > _b ? _a : _b; })

/* network stuff... */

static int listensock, sockfd;
static int isclient = 1;

static void error(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

int initServerNet(int port){
	int reuse = 1;
	struct sockaddr_in serv_addr;
	listensock = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
	/* NOTE: might not need the above if you make sure the client closes first */

	if (listensock < 0)
		error("ERROR opening socket");

	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(port);
	
	if (bind(listensock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
		error("ERROR on binding");
		
	fprintf(stderr, "listening on port %i...\n",port);
	listen(listensock,1);
	socklen_t clilen;
	struct sockaddr_in  cli_addr;
	sockfd = accept(listensock, (struct sockaddr *) &cli_addr, &clilen);
	if (sockfd < 0)
		error("error on accept");
	close(listensock);
	fprintf(stderr, "connection made, starting session...\n");
	/* at this point, should be able to send/recv on sockfd */
	return 0;
}



static int initClientNet(char* hostname, int port)
{
	struct sockaddr_in serv_addr;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	struct hostent *server;
	if (sockfd < 0)
		error("ERROR opening socket");
	server = gethostbyname(hostname);
	
	if (server == NULL) {
		fprintf(stderr,"ERROR, no such host\n");
		exit(0);
	}
	
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	memcpy(&serv_addr.sin_addr.s_addr,server->h_addr,server->h_length);
	serv_addr.sin_port = htons(port);

	if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0)
		error("ERROR connecting");

	

	return 0;

};
static int shutdownNetwork()
{
	shutdown(sockfd,2);
	unsigned char dummy[64];
	ssize_t r;
	do {
		r = recv(sockfd,dummy,64,0);
	} while (r != 0 && r != -1);
	close(sockfd);
	return 0;
}

/* end network stuff. */


static const char* usage =
"Usage: %s [OPTIONS]...\n"
"Secure chat (CCNY computer security project).\n\n"
"   -c, --connect HOST  Attempt a connection to HOST.\n"
"   -l, --listen        Listen for new connections.\n"
"   -p, --port    PORT  Listen or connect on PORT (defaults to 1337).\n"
"   -h, --help          show this message and exit.\n";

/* Append message to transcript with optional styling.  NOTE: tagnames, if not
 * NULL, must have it's last pointer be NULL to denote its end.  We also require
 * that messsage is a NULL terminated string.  If ensurenewline is non-zero, then
 * a newline may be added at the end of the string (possibly overwriting the \0
 * char!) and the view will be scrolled to ensure the added line is visible.  */
static void tsappend(char* message, char** tagnames, int ensurenewline)
{
	GtkTextIter t0;
	gtk_text_buffer_get_end_iter(tbuf,&t0);
	size_t len = g_utf8_strlen(message,-1);
	if (ensurenewline && message[len-1] != '\n')
		message[len++] = '\n';
	gtk_text_buffer_insert(tbuf,&t0,message,len);
	GtkTextIter t1;
	gtk_text_buffer_get_end_iter(tbuf,&t1);
	/* Insertion of text may have invalidated t0, so recompute: */
	t0 = t1;
	gtk_text_iter_backward_chars(&t0,len);
	if (tagnames) {
		char** tag = tagnames;
		while (*tag) {
			gtk_text_buffer_apply_tag_by_name(tbuf,*tag,&t0,&t1);
			tag++;
		}
	}
	if (!ensurenewline) return;
	gtk_text_buffer_add_mark(tbuf,mark,&t1);
	gtk_text_view_scroll_to_mark(tview,mark,0.0,0,0.0,0.0);
	gtk_text_buffer_delete_mark(tbuf,mark);
}

#include <openssl/evp.h>
#include <openssl/err.h>

static void sendMessage(GtkWidget* w /* <-- msg entry widget */, gpointer /* data */)
{
	char* tags[2] = {"self",NULL};
	tsappend("me: ",tags,0);
	GtkTextIter mstart; /* start of message pointer */
	GtkTextIter mend;   /* end of message pointer */
	gtk_text_buffer_get_start_iter(mbuf,&mstart);
	gtk_text_buffer_get_end_iter(mbuf,&mend);
	char* message = gtk_text_buffer_get_text(mbuf,&mstart,&mend,1); // this will have to be encrypted <--------------------------------------
	size_t len = g_utf8_strlen(message,-1);
	/* XXX we should probably do the actual network stuff in a different
	 * thread and have it call this once the message is actually sent. */
	ssize_t nbytes;
	if ((nbytes = send(sockfd,message,len,0)) == -1)
		error("send failed");

	tsappend(message,NULL,1);
	free(message);
	/* clear message text and reset focus */
	gtk_text_buffer_delete(mbuf,&mstart,&mend);
	gtk_widget_grab_focus(w);
}



static gboolean shownewmessage(gpointer msg)
{
	char* tags[2] = {"friend",NULL};
	char* friendname = "mr. friend: ";
	tsappend(friendname,tags,0);
	char* message = (char*)msg;
	tsappend(message,NULL,1);
	free(message);
	return 0;
}

// Function to write data to a file
void writeFile(const char *filename, const char *data) {
	    FILE *file;
	    // Open the file for writing (overwrite mode)
	    file = fopen(filename, "w");
	    if (file == NULL) {
		perror("Error opening file for writing");
		return;
	    }
	    // Write data to the file
	    fprintf(file, "%s\n", data);
	    // Close the file
	    fclose(file);
}


// Function to read data from a file and return as a string
char* readFile(const char *filename) {
	    FILE *file;
	    char *buffer = NULL; // Buffer to store read data
	    long length;
	    size_t result;
	    // Open the file for reading
	    file = fopen(filename, "r");
	    if (file == NULL) {
		perror("Error opening file for reading");
		return NULL;
	    }
	    // Get file length
	    fseek(file, 0, SEEK_END);
	    length = ftell(file);
	    rewind(file);
	    // Allocate memory for the buffer
	    buffer = (char*) malloc(length + 1);
	    if (buffer == NULL) {
		perror("Memory error");
		fclose(file);
		return NULL;
	    }
	    // Read data from the file
	    result = fread(buffer, 1, length, file);
	    if (result != length) {
		perror("Reading error");
		fclose(file);
		free(buffer);
		return NULL;
	    }
	    // Null-terminate the string
	    buffer[length] = '\0';
	    // Close the file
	    fclose(file);
	    return buffer;
}


int main(int argc, char *argv[])
{
	if (init("params") != 0) { //read p q and g from /params
		fprintf(stderr, "could not read DH params from file 'params'\n");
		return 1;
	}

	// define long options
	static struct option long_opts[] = {
		{"connect",  required_argument, 0, 'c'},
		{"listen",   no_argument,       0, 'l'},
		{"port",     required_argument, 0, 'p'},
		{"help",     no_argument,       0, 'h'},
		{0,0,0,0}
	};
	// process options:
	char c;
	int opt_index = 0;
	int port = 1337;
	char hostname[HOST_NAME_MAX+1] = "localhost";
	hostname[HOST_NAME_MAX] = 0;


	while ((c = getopt_long(argc, argv, "c:lp:h", long_opts, &opt_index)) != -1) {
		switch (c) {
			case 'c':
				if (strnlen(optarg,HOST_NAME_MAX))
					strncpy(hostname,optarg,HOST_NAME_MAX);
				break;
			case 'l':
				isclient = 0;
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 'h':
				printf(usage,argv[0]);
				return 0;
			case '?':
				printf(usage,argv[0]);
				return 1;
		}
	}
		int is_listener = 0; // Flag to indicate if this instance is the listener

	    // Check if this instance is the listener
	    if (argc > 1 && strcmp(argv[1], "-l") == 0) {
		is_listener = 1;
	    };
	    
// in short i have created a flag to determine which client i am working with. this allows me to manually perform 3DH and handle instances separately.	
	
	// Track the client based on the instance
        if (is_listener) {
	    // Perform actions specific to the listener instance
	    printf("Listener instance accepted a new client.\n");
	    NEWZ(b);//private
	    NEWZ(B);
	    dhGen(b, B);

	    // Convert B to a string
	    char* B_str = mpz_get_str(NULL, 10, B);
	    writeFile("B.txt",B_str); //send B
	
		
	//ephemeral keys
	    NEWZ(y);
	    NEWZ(Y);
	    dhGen(y,Y);
	    
	    
	// Convert Y to a string
	    char* Y_str = mpz_get_str(NULL, 10, Y);
	    writeFile("Y.txt",Y_str); //send Y
	    
 	//receive A from connector instance
	   char* A_recv= readFile("A.txt");
	   //printf("We received: %s\n",A_recv); //<- test to see if read and then clear worked
	   mpz_t A; 
	   mpz_init(A);
	   
	    if (mpz_set_str(A, A_recv, 10) != 0) {
		printf("Error: Invalid string for conversion to mpz_t\n");
		return 1;
	    }
		
		
	    free(A_recv); //free memory

	
	//receive X from connector instance
	   char* X_recv= readFile("X.txt");
	   //printf("We received: %s\n",X_recv); //<- test to see if read and then clear worked
	   mpz_t X; 
	   mpz_init(X);
	  
	    if (mpz_set_str(X, X_recv, 10) != 0) {
		printf("Error: Invalid string for conversion to mpz_t\n");
		return 1;
	    }
		
		
	    free(X_recv); //free memory
	
	//calculate 3dh value
	unsigned char keyBuf[PATH_MAX];
	 size_t bufLen = PATH_MAX;
	 //gmp_printf("b = %Zd, B = %Zd, y = %Zd, Y = %Zd, A = %Zd, X = %Zd\n", b,B,y,Y,A,X); //<-- testing in case any variable wasnt read correctly

	 dh3Final(b, B, y, Y, A, X, keyBuf, bufLen); //<--- this call should work, but can run into segmentation faults. 

	 printf("Our k1 value is %s\n",keyBuf);
	
	
	    }
	 else {// Perform actions specific to the connector instance
	    printf("Connector instance accepted a new client.\n");

	    NEWZ(a); //private
	    NEWZ(A);
	    dhGen(a, A);
	
	//now we'll set up ephemeral keys
	    NEWZ(x);
	    NEWZ(X);
	    dhGen(x,X);
	    
	    //receive B from listener instance
	   char* B_recv= readFile("B.txt");
//printf("We received for B: %s\n",B_recv); //<- test to see if read and then clear worked
	   mpz_t B; 
	   mpz_init(B);
	   
	    if (mpz_set_str(B, B_recv, 10) != 0) {
		printf("Error: Invalid string for conversion to mpz_t\n");
		return 1;
	    }
		
		
	    free(B_recv); //free memory
	
	
	// Convert A to a string
	    char* A_str = mpz_get_str(NULL, 10, A);
	    writeFile("A.txt",A_str); //send A
	
	// Convert X to a string
	    char* X_str = mpz_get_str(NULL, 10, X);
	    writeFile("X.txt",X_str); //send X
	
	
	
	   
	  //receive Y from connector instance
	   char* Y_recv= readFile("Y.txt");
//printf("We received for Y: %s\n",Y_recv); //<- test to see if read and then clear worked
	   mpz_t Y; 
	mpz_init(Y);
	    if (mpz_set_str(Y, Y_recv, 10) != 0) {
		printf("Error: Invalid string for conversion to mpz_t\n");
		return 1;
	    }
		
	    free(Y_recv); //free memory
	    

	 
	    //calculate k1
	unsigned char keyBuf[PATH_MAX];

	 size_t bufLen = PATH_MAX;
	 //gmp_printf("a = %Zd, A = %Zd, x = %Zd, X = %Zd, B = %Zd, Y = %Zd\n", a,A,x,X,B,Y); <-- testing in case any variable wasnt read correctly

	 dh3Final(a, A, x, X, B, Y, keyBuf, bufLen); //<--- this call should work, but can run into segmentation faults. 

	 printf("Our k2 value is %s\n",keyBuf);
}
	 
	/* NOTE: might want to start this after gtk is initialized so you can
	 * show the messages in the main window instead of stderr/stdout.  If
	 * you decide to give that a try, this might be of use:
	 * https://docs.gtk.org/gtk4/func.is_initialized.html */
	if (isclient) {
		initClientNet(hostname,port);
	} else {
		initServerNet(port);
	}

	/* setup GTK... */
	GtkBuilder* builder;
	GObject* window;
	GObject* button;
	GObject* transcript;
	GObject* message;
	GError* error = NULL;
	gtk_init(&argc, &argv);
	builder = gtk_builder_new();
	if (gtk_builder_add_from_file(builder,"layout.ui",&error) == 0) {
		g_printerr("Error reading %s\n", error->message);
		g_clear_error(&error);
		return 1;
	}
	mark  = gtk_text_mark_new(NULL,TRUE);
	window = gtk_builder_get_object(builder,"window");
	g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
	transcript = gtk_builder_get_object(builder, "transcript");
	tview = GTK_TEXT_VIEW(transcript);
	message = gtk_builder_get_object(builder, "message");
	tbuf = gtk_text_view_get_buffer(tview);
	mbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(message));
	button = gtk_builder_get_object(builder, "send");
	g_signal_connect_swapped(button, "clicked", G_CALLBACK(sendMessage), GTK_WIDGET(message));
	gtk_widget_grab_focus(GTK_WIDGET(message));
	GtkCssProvider* css = gtk_css_provider_new();
	gtk_css_provider_load_from_path(css,"colors.css",NULL);
	gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
			GTK_STYLE_PROVIDER(css),
			GTK_STYLE_PROVIDER_PRIORITY_USER);

	/* setup styling tags for transcript text buffer */
	gtk_text_buffer_create_tag(tbuf,"status","foreground","#657b83","font","italic",NULL);
	gtk_text_buffer_create_tag(tbuf,"friend","foreground","#6c71c4","font","bold",NULL);
	gtk_text_buffer_create_tag(tbuf,"self","foreground","#268bd2","font","bold",NULL);

	/* start receiver thread: */
	if (pthread_create(&trecv,0,recvMsg,0)) {
		fprintf(stderr, "Failed to create update thread.\n");
	}

	gtk_main();

	shutdownNetwork();
	return 0;
}

/* thread function to listen for new messages and post them to the gtk
 * main loop for processing: */
void* recvMsg(void*)
{
	size_t maxlen = 512;
	char msg[maxlen+2]; /* might add \n and \0 */
	ssize_t nbytes;
	while (1) {
		if ((nbytes = recv(sockfd,msg,maxlen,0)) == -1)
			error("recv failed");
		if (nbytes == 0) {
			/* XXX maybe show in a status message that the other
			 * side has disconnected. */
			return 0;
		}
		char* m = malloc(maxlen+2);
		memcpy(m,msg,nbytes); 
		if (m[nbytes-1] != '\n')
			m[nbytes++] = '\n';
		m[nbytes] = 0;
		g_main_context_invoke(NULL,shownewmessage,(gpointer)m);
	}
	return 0;
}

