#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "windivert.h"

#define IP_HL(ip)               (ip->HdrLength<<2)
#define TH_OFF(th)				(th->HdrLength<<2)
#define _CRT_SECURE_NO_WARNINGS
#define MAXBUF 0xFFFF
#define MAXLEN	128
#define MAX_PACKET_SIZE 65536

/*
* url List for filter
*/
struct node {
	struct node* pre;
	struct node* nxt;
	char *url;
};

/*
* Pre-fabricated packets.
*/
typedef struct
{
	WINDIVERT_IPHDR  ip;
	WINDIVERT_TCPHDR tcp;
} PACKET, *PPACKET;

typedef struct
{
	PACKET header;
	UINT8 data[];
} DATAPACKET, *PDATAPACKET;

/*
* THe block page contents.
*/
const char block_data[] =
"HTTP/1.1 200 OK\r\n"
"Connection: close\r\n"
"Content-Type: text/html\r\n"
"\r\n"
"<!doctype html>\n"
"<html>\n"
"\t<head>\n"
"\t\t<title>BLOCKED!</title>\n"
"\t</head>\n"
"\t<body>\n"
"\t\t<h1>BLOCKED!</h1>\n"
"\t\t<hr>\n"
"\t\t<p>This URL has been blocked!</p>\n"
"\t</body>\n"
"</html>\n";

/*
* Prototypes
*/

typedef int(*Compare)(const char *, const char *);

static void PacketInit(PPACKET packet);
static void filterListInit(struct node* root, const char *fName);
void insert(char* url, struct node** tree, Compare cmp);
void remove_extra_whitespaces(char* input, char* output);
int checkUrl(char* url, struct node* tree, Compare cmp);
char *parseUrl(char *packet);
void writeLog(char *url);

int CmpStr(const char *a, const char *b)
{
	char outA[MAXLEN];
	char outB[MAXLEN];

	memset(outA, '\0', sizeof(outA));
	memset(outB, '\0', sizeof(outB));

	remove_extra_whitespaces(a, outA);
	remove_extra_whitespaces(b, outB);

	if (strstr(outA, outB)) {
		return 0;
	}

	return (strcmp(outA, outB));     // string comparison instead of pointer comparison
}

void printChkList(struct node *root)
{
	if (root != NULL) {
		printChkList(root->pre);
		printf("[+] Added: %s\n", root->url);     // string type
		printChkList(root->nxt);
	}
}

/*
* Entry.
*/
int __cdecl main(int argc, char **argv)
{
	HANDLE handle;
	WINDIVERT_ADDRESS addr;
	UINT8 packet[MAXBUF];
	UINT packet_len;
	UINT size_ip;
	UINT size_tcp;
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_TCPHDR tcp_header;
	PVOID payload;
	UINT payload_len;
	PACKET reset0;
	PPACKET reset = &reset0;
	PACKET finish0;
	PPACKET finish = &finish0;
	PDATAPACKET blockpage;
	UINT16 blockpage_len;
	INT16 priority = 404;       // Arbitrary.
	unsigned i;
	struct node *p_root = NULL;
	char accessUrl[BUFSIZ];


	if (argc <= 1) {
		fprintf(stderr, "usage: %s blacklist.txt\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	// Initialize the pre-frabricated packets:
	blockpage_len = sizeof(DATAPACKET) + sizeof(block_data) - 1;
	blockpage = (PDATAPACKET)malloc(blockpage_len);

	if (blockpage == NULL) {
		fprintf(stderr, "error: memory allocation failed\n");
		exit(EXIT_FAILURE);
	}

	PacketInit(&blockpage->header);
	blockpage->header.ip.Length = htons(blockpage_len);
	blockpage->header.tcp.SrcPort = htons(80);
	blockpage->header.tcp.Psh = 1;
	blockpage->header.tcp.Ack = 1;
	memcpy(blockpage->data, block_data, sizeof(block_data) - 1);
	PacketInit(reset);
	reset->tcp.Rst = 1;
	reset->tcp.Ack = 1;
	PacketInit(finish);
	finish->tcp.Fin = 1;
	finish->tcp.Ack = 1;

	//////////////////////////////////////////////////////////////////////////////////////
	filterListInit(&p_root, argv[1]);
	printChkList(p_root);
	//////////////////////////////////////////////////////////////////////////////////////

	// Open the Divert device:
	handle = WinDivertOpen(
		"outbound && "              // Outbound traffic only
		"ip && "                    // Only IPv4 supported
		"tcp.DstPort == 80 && "     // HTTP (port 80) only
		"tcp.PayloadLength > 0",    // TCP data packets only
		WINDIVERT_LAYER_NETWORK, priority, 0
	);

	if (handle == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "error: failed to open the WinDivert device (%d)\n", GetLastError());
		exit(EXIT_FAILURE);
	}
	printf("OPENED WinDivert\n");

	// Main loop:
	while (TRUE)
	{
		if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len))
		{
			fprintf(stderr, "warning: failed to read packet (%d)\n",
				GetLastError());
			continue;
		}

		if (packet != NULL) {
			ip_header = (PWINDIVERT_IPHDR *)packet;
			size_ip = IP_HL(ip_header);

			tcp_header = (PWINDIVERT_TCPHDR *)(packet + size_ip);
			size_tcp = TH_OFF(tcp_header);

			payload = (PVOID *)(packet + (size_ip + size_tcp));
			payload_len = ntohs(ip_header->Length) - (size_ip + size_tcp);
		}

		if (!(checkUrl(parseUrl(payload), p_root, (Compare)CmpStr))) {
			// Packet does not match the blacklist; simply reinject it.
			printf("=====================================Allowed=====================================\n");
			if (!WinDivertSend(handle, packet, packet_len, &addr, NULL))
			{
				fprintf(stderr, "warning: failed to reinject packet (%d)\n",
					GetLastError());
			}
			continue;
		}
		printf("=====================================Blocked=====================================\n");
		// The URL matched the blacklist; we block it by hijacking the TCP
		// connection.
		// (1) Send a TCP RST to the server; immediately closing the
		//     connection at the server's end.
		reset->ip.SrcAddr = ip_header->SrcAddr;
		reset->ip.DstAddr = ip_header->DstAddr;
		reset->tcp.SrcPort = tcp_header->SrcPort;
		reset->tcp.DstPort = htons(80);
		reset->tcp.SeqNum = tcp_header->SeqNum;
		reset->tcp.AckNum = tcp_header->AckNum;
		WinDivertHelperCalcChecksums((PVOID)reset, sizeof(PACKET), 0);
		if (!WinDivertSend(handle, (PVOID)reset, sizeof(PACKET), &addr, NULL))
		{
			fprintf(stderr, "warning: failed to send reset packet (%d)\n",
				GetLastError());
		}

		// (2) Send the blockpage to the browser:
		blockpage->header.ip.SrcAddr = ip_header->DstAddr;
		blockpage->header.ip.DstAddr = ip_header->SrcAddr;
		blockpage->header.tcp.DstPort = tcp_header->SrcPort;
		blockpage->header.tcp.SeqNum = tcp_header->AckNum;
		blockpage->header.tcp.AckNum =
			htonl(ntohl(tcp_header->SeqNum) + payload_len);
		WinDivertHelperCalcChecksums((PVOID)blockpage, blockpage_len, 0);
		addr.Direction = !addr.Direction;     // Reverse direction.

		if (!WinDivertSend(handle, (PVOID)blockpage, blockpage_len, &addr,
			NULL))
		{
			fprintf(stderr, "warning: failed to send block page packet (%d)\n",
				GetLastError());
		}

		// (3) Send a TCP FIN to the browser; closing the connection at the 
		//     browser's end.
		finish->ip.SrcAddr = ip_header->DstAddr;
		finish->ip.DstAddr = ip_header->SrcAddr;
		finish->tcp.SrcPort = htons(80);
		finish->tcp.DstPort = tcp_header->SrcPort;
		finish->tcp.SeqNum =
			htonl(ntohl(tcp_header->AckNum) + sizeof(block_data) - 1);
		finish->tcp.AckNum =
			htonl(ntohl(tcp_header->SeqNum) + payload_len);
		WinDivertHelperCalcChecksums((PVOID)finish, sizeof(PACKET), 0);
		if (!WinDivertSend(handle, (PVOID)finish, sizeof(PACKET), &addr, NULL))
		{
			fprintf(stderr, "warning: failed to send finish packet (%d)\n",
				GetLastError());
		}
	}
}

/*
* Initialize a PACKET.
*/
static void PacketInit(PPACKET packet)
{
	memset(packet, 0, sizeof(PACKET));
	packet->ip.Version = 4;
	packet->ip.HdrLength = sizeof(WINDIVERT_IPHDR) / sizeof(UINT32);
	packet->ip.Length = htons(sizeof(PACKET));
	packet->ip.TTL = 64;
	packet->ip.Protocol = IPPROTO_TCP;
	packet->tcp.HdrLength = sizeof(WINDIVERT_TCPHDR) / sizeof(UINT32);
}

static void filterListInit(struct node* root, const char *fName) {
	char url[MAXLEN];
	char *httpStr = "http://";

	FILE *fd = fopen(fName, "r");
	if (fd == NULL) {
		fprintf(stderr, "error: could not open blacklist file %s\n",
			fName);
		exit(EXIT_FAILURE);
	}

	while (fgets(url, sizeof(url), fd)) {
		insert(url + strlen(httpStr), root, (Compare)CmpStr);
	}
	fclose(fd);
}

void insert(char* url, struct node** tree, Compare cmp) {
	int res;

	if (*tree == NULL) {
		*tree = (struct node*) malloc(sizeof(struct node));
		(*tree)->url = malloc(strlen(url) + 1);     // memory for key
		strcpy((*tree)->url, url);                   // copy the key
		(*tree)->pre = NULL;
		(*tree)->nxt = NULL;
		//printf(  "\nnew node for %s" , key);
	}
	else {
		res = cmp(url, (*tree)->url);
		if (res < 0)
			insert(url, &(*tree)->pre, cmp);
		else if (res > 0)
			insert(url, &(*tree)->nxt, cmp);
		else                                            // key already exists
			printf("URL: %s already in tree\n", url);
	}
}

int checkUrl(char* url, struct node* tree, Compare cmp)  // no need for **
{
	int res;
	
	if (tree != NULL) {
		tree->url = strtok(tree->url, "\n");
		res = cmp(url, tree->url);
		printf("%s::%s\n", url, tree->url);
		if (res < 0)
			return checkUrl(url, tree->pre, cmp);
		else if (res > 0)
			return checkUrl(url, tree->nxt, cmp);
		else {
			printf("\n[+] Found: %s\n", url);     // string type
			writeLog(url);
			return 1;
		}
	}
	else printf("\n[-] Not in tree: %s\n", url);
	return 0;
}

char *parseUrl(char *packet) {
	static const char *host_str = "Host: ";
	char tmp[MAX_PACKET_SIZE] = { 0, };
	char *pTmp = NULL;
	strcpy(tmp, packet);

	pTmp = strstr(tmp, host_str);
	pTmp = strtok(pTmp + sizeof(host_str) - 2, "\n");

	return pTmp;
}

void remove_extra_whitespaces(char* input, char* output)
{
	int inputIndex = 0;
	int outputIndex = 0;
	while (input[inputIndex] != '\0')
	{
		output[outputIndex] = input[inputIndex];

		if (input[inputIndex] == ' ' || input[inputIndex] == '\n')
		{
			while (input[inputIndex + 1] == ' ' || input[inputIndex + 1] == '\n')
			{
				// skip over any extra spaces
				inputIndex++;
			}
		}
		outputIndex++;
		inputIndex++;
	}
	// null-terminate output
	output[outputIndex] = '\0';
}

void writeLog(char *url) {
	FILE *fd;

	fd = fopen("log.txt", "a");
	fprintf(fd, "[+] Blocked: %s\n", url);
	fclose(fd);
	printf("[+] Append Log\n");
}