/*
 * SIP Registration Agent -- by ww@styx.org
 * 
 * This program is Free Software, released under the GNU General
 * Public License v2.0 http://www.gnu.org/licenses/gpl
 *
 * This program will register to a SIP proxy using the contact
 * supplied on the command line. This is useful if, for some 
 * reason your SIP client cannot register to the proxy itself.
 * For example, if your SIP client registers to Proxy A, but
 * you want to be able to recieve calls that arrive at Proxy B,
 * you can use this program to register the client's contact
 * information to Proxy B.
 *
 * This program requires the eXosip library. To compile,
 * assuming your eXosip installation is in /usr/local,
 * use something like:
 *
 * gcc -O2 -I/usr/local/include -L/usr/local/lib sipreg.c \
 *         -o sipreg \
 *         -leXosip2 -losip2 -losipparser2 -lpthread
 *
 * It should compile and run on any POSIX compliant system
 * that supports pthreads.
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <syslog.h>
#include <pthread.h>
#include <time.h>
#include <sys/select.h>
#include <string.h>


#include <osip2/osip_mt.h>
#include <eXosip2/eXosip.h>



typedef char					int8;
typedef unsigned char			uint8;
typedef short					int16;
typedef unsigned short			uint16;
typedef int						int32;
typedef unsigned int			uint32;
typedef int						int64;
typedef unsigned int			uint64;




#define PROG_NAME "sipreg"
#define PROG_VER  "1.0"
#define UA_STRING "SipReg v" PROG_VER
#define SYSLOG_FACILITY LOG_DAEMON



#define dbg(fmt, args...)  do {	\
	fprintf(stderr, fmt, ##args);	\
	fprintf(stderr, "=======> File : %s, Line : %d, Func: %s\n",	__FILE__, __LINE__, __func__);	\
	fflush(stderr);	\
} while (0)
#define syslog_wrapper(a,b...) fprintf(stdout,b);fprintf(stdout,"\n")


typedef struct regparam_t {
  int regid;
  int expiry;
  int auth;
} regparam_t;


//
int port = 9999;
char *contact = NULL;
char *fromuser = "sip:user001@kdomain001";
const char *localip = NULL;
const char *firewallip = NULL;
char *proxy = "sip:192.168.0.172:5060";
char *username = "user001";
char *password = "user001";

char *option_proxy="192.168.0.172";


//register
regparam_t regparam;
struct osip_thread *register_thread;
osip_message_t *regist=NULL;
uint64 register_time=0;


//context event
struct eXosip_t *context_eXosip=NULL;
eXosip_event_t *event=NULL;



//invite
osip_message_t *invite=NULL;

//message
osip_message_t *message=NULL;
uint64 message_time=0;

//answer
osip_message_t *answer=NULL;



//timer
uint64 time_now_ms(){
	int32 ret=0;
	struct timespec t;
	ret=clock_gettime(CLOCK_MONOTONIC, &t);
	if(ret!=0){
		return 0;
	}
	return t.tv_sec*1000+t.tv_nsec/(1000*1000);
}
uint64 time_now_s(){
	int32 ret=0;
	struct timespec t;
	ret=clock_gettime(CLOCK_MONOTONIC, &t);
	if(ret!=0){
		return 0;
	}
	return t.tv_sec;
}



//主动发送一个INVITE请求，携带SDP信息
void invite_send(const char *to, const char *from)
{
  char reference[128] = "invite test";
  int ret;

  #if 0
  //PROXY
  ret=eXosip_set_option(context_eXosip, EXOSIP_OPT_SET_IPV4_FOR_GATEWAY, (void *)option_proxy);
  if(ret!=0){
	dbg("exosip set option --IPV4 gateway fail.");
	return 0;
  }
  //DNS DISABLE
  int v=0;
  ret=eXosip_set_option(context_eXosip, EXOSIP_OPT_DNS_CAPABILITIES, (void *)&v);
  if(ret!=0){
	dbg("exosip set option --DNS diable fail.");
	return 0;
  }
  #endif


  //
  ret = eXosip_call_build_initial_invite (context_eXosip, &invite, to, from, NULL, "Invite");
  if (0 != ret)
  {
    dbg("eXosip_call_build_initial_invite failure!\n");
	return ;
  }

  //support header
  osip_message_set_supported (invite, "100rel");

  //other headers
  osip_message_set_header(message, "CHANNEL", "7");
  osip_message_set_header(message, "STREAM", "1");

  //sdp
  {
	char sdp[4096];
	char localip[128];
	ret = eXosip_guess_localip (context_eXosip, AF_INET, localip, 128);
	if (0 != ret)
    {
      dbg("eXosip_guess_localip failure!");
  	  return;
    }
	snprintf (sdp, sizeof(sdp),
	"v=0\r\n"
	"o=josua 0 0 IN IP4 %s\r\n"
	"s=conversation\r\n"
	"c=IN IP4 %s\r\n"
	"t=0 0\r\n"
	"m=audio %s RTP/AVP 0 8 101\r\n"
	"a=rtpmap:0 PCMU/8000\r\n"
	"a=rtpmap:8 PCMA/8000\r\n"
	"a=rtpmap:101 telephone-event/8000\r\n"
	"a=fmtp:101 0-11\r\n", localip, localip, "10000");

	dbg("SDP:\n%s", sdp);
	
	ret = osip_message_set_body (invite, sdp, strlen(sdp));
	if (0 != ret)
    {
      dbg("osip_message_set_body failure!");
  	  return;
    }
	
	ret = osip_message_set_content_type (invite, "application/sdp");
	if (0 != ret)
    {
      dbg("osip_message_set_content_type failure!");
  	  return;
    }
  }

  //send invite message
  //eXosip_lock (context_eXosip);
  ret = eXosip_call_send_initial_invite (context_eXosip, invite);
  if (ret > 0)  
  {
  	  dbg("Xosip_call_send_initial_invite success\n");
	  ret = eXosip_call_set_reference (context_eXosip, ret, reference);
	  if (0 == ret)
	  {
	  	dbg("eXosip_call_set_reference success.");
	  }else{
		dbg("eXosip_call_set_reference faul.");
		return ;
	  }
	
  }  
  //eXosip_unlock (context_eXosip);  

  return ;
}

void invite_send2(const char *to, const char *from){

	int ret=0;

	
	ret=eXosip_message_build_request(context_eXosip, &invite, "invite", to, from, NULL);
	if(ret!=0){
		dbg("invite build fail.");
		return ;
	}

	#if 0
	ret=eXosip_refer_build_request(context_eXosip, &invite, NULL, from, to, "sip:192.168.0.172:5060");
	if(ret!=0){
		dbg("refer build fail.");
		return ;
	}
	#endif
	
	char sdp[4096];
	char localip[128];
	ret = eXosip_guess_localip (context_eXosip, AF_INET, localip, 128);
	if (0 != ret)
    {
      dbg("eXosip_guess_localip failure!");
  	  return;
    }

	//sdp
	snprintf (sdp, sizeof(sdp),
	"v=0\r\n"
	"o=josua 0 0 IN IP4 %s\r\n"
	"s=conversation\r\n"
	"c=IN IP4 %s\r\n"
	"t=0 0\r\n"
	"m=audio %s RTP/AVP 0 8 101\r\n"
	"a=rtpmap:0 PCMU/8000\r\n"
	"a=rtpmap:8 PCMA/8000\r\n"
	"a=rtpmap:101 telephone-event/8000\r\n"
	"a=fmtp:101 0-11\r\n", localip, localip, "10000");
	
	ret = osip_message_set_body (invite, sdp, strlen(sdp));
	if (0 != ret)
    {
      dbg("osip_message_set_body failure!");
  	  return;
    }
	
	ret = osip_message_set_content_type (invite, "application/sdp");
	if (0 != ret)
    {
      dbg("osip_message_set_content_type failure!");
  	  return;
    }

	ret=eXosip_message_send_request(context_eXosip, invite);
	if(ret!=0){
		dbg("invite send fail.");
		return ;
	}
	return ;
}


//主动发送一个MESSAGE包，携带扩展的头域 XML信息
void message_send(const char *to, const char *from){

	int ret=0;
	ret=eXosip_message_build_request(context_eXosip, &message, "MESSAGE", to, from, NULL);
	if(ret!=0){
		dbg("message build fail.");
		return ;
	}

	//support header
	osip_message_set_supported(message, "command");

	//other headers
	osip_message_set_header(message, "CHANNEL", "7");
	osip_message_set_header(message, "STREAM", "1");
	osip_message_set_header(message, "COMMAND", "32");
	 

	char xml[1024];
	#if 1
	//snprintf(xml ,sizeof(xml), "<?xml version=1.0 encoding=utf-8?>\r\n<msg>message text</msg>\r\n");
	snprintf(xml, sizeof(xml), 
		"<?xml version=\'1.0\' encoding=\"\'UTF-8\'?>\r\n"
		"<note>\r\n"
			"<to>George</to>\r\n"
			"<from>John</from>\r\n"
			"<heading>Reminder</heading>\r\n"
			"<body>Don't forget the meeting!</body>\r\n"
		"</note>\r\n");
	#else
	snprintf(xml, sizeof(xml), "<font face=\"Arial, sans-serif\" size=\"2\">message text</font>");
	#endif
	
	ret = osip_message_set_body (message, xml, strlen(xml));
	if (0 != ret)
    {
      dbg("set body fail.!");
  	  return;
    }
	
	ret = osip_message_set_content_type (message, "application/xml");
	if (0 != ret)
    {
      dbg("set content type fail.!");
  	  return;
    }
	
	ret=eXosip_message_send_request(context_eXosip, message);
	if(ret!=0){
		dbg("message send fail.");
		return ;
	}

	return ;
}

//收到一个MESSAGE消息后的处理
void message_recv(eXosip_event_t *event){

	int ret=0;
	osip_header_t *header=NULL;

	#if 0
	ret=osip_message_header_get_byname(event->request, "Content-Length", 0, &header);
	if(ret!=0){
		dbg("osip message header get byname fail.");
		return ;
	}
	dbg("hname:%s--hvalue:%s", header->hname, header->hvalue);
	#endif

	//build answer 200 ok
	osip_message_t *message_answer=NULL;
	ret=eXosip_message_build_answer(context_eXosip, event->tid, 200, &message_answer);
	if(ret!=0){
		dbg("exosip message build answer fail.");
		return ;
	}

	//support
	osip_message_set_supported(message_answer, "command");

	//other HDR
	osip_message_set_header(message_answer, "CHANNEL", "7");
	osip_message_set_header(message_answer, "STREAM", "1");
	osip_message_set_header(message_answer, "COMMAND", "32");
	
	//xml
	char xml[1024];
	snprintf(xml, sizeof(xml), 
		"<?xml version=\'1.0\' encoding=\"\'UTF-8\'?>\r\n"
		"<note>\r\n"
			"<to>George</to>\r\n"
			"<from>John</from>\r\n"
			"<heading>Reminder</heading>\r\n"
			"<body>Don't forget the meeting!</body>\r\n"
		"</note>\r\n");
	ret = osip_message_set_body (message_answer, xml, strlen(xml));
	if (0 != ret)
    {
      dbg("set body fail.!");
  	  return;
    }
	ret = osip_message_set_content_type (message_answer, "application/xml");
	if (0 != ret)
    {
      dbg("set content type fail.!");
  	  return;
    }

	//send 200 ok
	ret=eXosip_message_send_answer(context_eXosip, event->tid, 200, message_answer);
	if(ret!=0){
		dbg("eXosip message send answer fail.");
		return ;
	}

	return ;
}

void sdp_complete_200ok(){
{
	int ret=0;
	char sdp[4096];
	char localip[128];
	ret = eXosip_guess_localip (context_eXosip, AF_INET, localip, 128);
	if (0 != ret)
    {
      dbg("eXosip_guess_localip failure!");
  	  return;
    }
	snprintf (sdp, sizeof(sdp),
	"v=0\r\n"
	"o=josua 0 0 IN IP4 %s\r\n"
	"s=conversation\r\n"
	"c=IN IP4 %s\r\n"
	"t=0 0\r\n"
	"m=audio %s RTP/AVP 0 8 101\r\n"
	"a=rtpmap:0 PCMU/8000\r\n"
	"a=rtpmap:8 PCMA/8000\r\n"
	"a=rtpmap:101 telephone-event/8000\r\n"
	"a=fmtp:101 0-11\r\n", localip, localip, "10000");

	dbg("SDP:\n%s", sdp);
	
	ret = osip_message_set_body (answer, sdp, strlen(sdp));
	if (0 != ret)
    {
      dbg("osip_message_set_body failure!");
  	  return;
    }
	
	ret = osip_message_set_content_type (answer, "application/sdp");
	if (0 != ret)
    {
      dbg("osip_message_set_content_type failure!");
  	  return;
    }
  }
  return ;
}




int main (int argc, char *argv[])
{
  int ret=0;

  TRACE_INITIALIZE (6, NULL);

  //exosip init
  context_eXosip = eXosip_malloc ();
  if(context_eXosip==NULL){
		dbg("eXosip malloc fail.");
		return 0;
  }
  ret=eXosip_init (context_eXosip);
  if(ret!=0){
    syslog_wrapper (LOG_ERR, "eXosip_init failed");
    return 0;
  }

  //proxy
  ret=eXosip_set_option(context_eXosip, EXOSIP_OPT_SET_IPV4_FOR_GATEWAY, (void *)option_proxy);
  if(ret!=0){
	dbg("exosip set option --IPV4 gateway fail.");
	return 0;
  }
  //dns
  #if 0
  int v=0;
  ret=eXosip_set_option(context_eXosip, EXOSIP_OPT_DNS_CAPABILITIES, (void *)&v);
  if(ret!=0){
	dbg("exosip set option --DNS diable fail.");
	return 0;
  }
  #else
  struct eXosip_dns_cache dns_cache;
  strcpy(dns_cache.host, "kdomain001");
  strcpy(dns_cache.ip, option_proxy);
  ret=eXosip_set_option(context_eXosip, EXOSIP_OPT_ADD_DNS_CACHE, &dns_cache);
  if(ret!=0){
	dbg("add dns cache fail.");
	return 0;
  }
  #endif
  
  //uac socket(uac port is 9999; UDP or TCP okay)
  if (eXosip_listen_addr (context_eXosip, IPPROTO_UDP, NULL, port, AF_INET, 0)) {
    syslog_wrapper (LOG_ERR, "eXosip_listen_addr failed");
    exit (1);
  }

  //localip===contract
  if (localip) {
    syslog_wrapper (LOG_INFO, "local address: %s", localip);
    eXosip_masquerade_contact (context_eXosip, localip, port);
  }
  if (firewallip) {
    syslog_wrapper (LOG_INFO, "firewall address: %s:%i", firewallip, port);
    eXosip_masquerade_contact (context_eXosip, firewallip, port);
  }
  
  eXosip_set_user_agent (context_eXosip, UA_STRING);

  //authentication--server answer:realm/nonce for authentication.
  if (username && password) {
    syslog_wrapper (LOG_INFO, "username: %s", username);
    syslog_wrapper (LOG_INFO, "password: %s", password);
	//nonce没有确定，其他的指定都没有用
    if (eXosip_add_authentication_info (context_eXosip, username, username, password, NULL, NULL)) {
      syslog_wrapper (LOG_ERR, "eXosip_add_authentication_info failed");
      exit (1);
    }
  }
  
  //register
  regparam.regid=0;
  regparam.expiry=60;
  regparam.auth=0;
  regparam.regid = eXosip_register_build_initial_register (context_eXosip, fromuser, 
		proxy, contact, regparam.expiry, &regist);
  if (regparam.regid < 1) {
      dbg("register build fail.");
      return 0;
  }
  ret = eXosip_register_send_register (context_eXosip, regparam.regid, regist);
  if (0 > ret) {
      dbg ("eXosip_register send fail.");
      return 0;
  }
  register_time=time_now_s();

  //message
  message_time=time_now_s();

  //loop
  while (1) {

	//regster
	if(time_now_s()-register_time > regparam.expiry/2){

		//eXosip_lock (context_eXosip);
		ret = eXosip_register_send_register (context_eXosip, regparam.regid, NULL);
   		if (0 > ret) {
      		dbg ("eXosip_register send fail.");
      		return 0;
    	}
		//eXosip_unlock (context_eXosip);
		register_time=time_now_s();
	}

	//message send.
	if(time_now_s()-message_time > 10){
		message_send("sip:user003@kdomain001", fromuser);
		message_time=time_now_s();
	}

	//event wait
    event = eXosip_event_wait (context_eXosip, 10, 0);
	if(event==NULL){
		dbg("event wait timeout.");
		continue;
	}
    eXosip_automatic_action (context_eXosip);


	switch (event->type) {

	  //注册成功
	  case EXOSIP_REGISTRATION_SUCCESS:
        dbg("register success.");
        break;

	  //注册失败
      case EXOSIP_REGISTRATION_FAILURE:
		dbg("register fail.");
        break;



	  
	  ///一个新的呼叫进来,发送180 RINGING, 因为RING是不会回复的，所以直接再发送200OK等待ACK
	  case EXOSIP_CALL_INVITE:
	  	dbg("a new invite comming...ring first");
		//ring
		ret=eXosip_call_send_answer(context_eXosip, event->tid, 180, NULL);
		if(ret!=0){
			dbg("call send answer 180 ringing fail.");
			return 0;
		}
		//200 ok +SDP,然后等待ACK
		ret=eXosip_call_build_answer(context_eXosip, event->tid, 200, &answer);
		if(ret!=0){
			dbg("call build answer fail.");
			return 0;
		}
		sdp_complete_200ok();
		ret=eXosip_call_send_answer(context_eXosip, event->tid, 200, answer);
		if(ret!=0){
			dbg("call send answer fail.");
			return 0;
		}
	  	break;
	  case EXOSIP_CALL_REINVITE:
	  	break;
		
	  //主动呼叫等待回复超时
	  case EXOSIP_CALL_NOANSWER:
	  	break;
	  case EXOSIP_CALL_PROCEEDING:
	  	break;
	  
	  //主动INVITE后收到RING
	  case EXOSIP_CALL_RINGING:
	  	dbg("ring back.");
	  	break;

	  //主动呼叫后收到被呼叫方的200 OK+SDP，回复一个ACK+SDP后,则开始媒体会话
	  case EXOSIP_CALL_ANSWERED:
	  	dbg("call answered,start rtp session.");
		
	  	break;
	  case EXOSIP_CALL_REDIRECTED:
	  	break;
	  case EXOSIP_CALL_REQUESTFAILURE:
	  	break;
	  case EXOSIP_CALL_SERVERFAILURE:
	  	break;
	  case EXOSIP_CALL_GLOBALFAILURE:
	  	break;

	  //200OK发送到呼叫方后，等待呼叫方的ACK，完成后媒体开始传输
	  case EXOSIP_CALL_ACK:
	  	break;

	  //任何一方发送CANCEL后的结果，收到CANCEL则断开媒体会话
	  case EXOSIP_CALL_CANCELLED:
	  	break;

	  //收到BYE后断开媒体会话
	  case EXOSIP_CALL_CLOSED:
	  	break;
  	  case EXOSIP_CALL_RELEASED:
	  	dbg("for event EXOSIP_CALL_RELEASED done.\n");
	  	break;





	  
	  //message
	  case EXOSIP_MESSAGE_NEW:
	  	dbg("new message comming.");
		message_recv(event);
	  	break;
	  case EXOSIP_MESSAGE_PROCEEDING:
	  	break;
	  case EXOSIP_MESSAGE_ANSWERED:
	  	dbg("message request answered.");
	  	break;
	  case EXOSIP_MESSAGE_REDIRECTED:
	  	break;
	  case EXOSIP_MESSAGE_REQUESTFAILURE:
	  	dbg("message request fail.");
		if(event->response->status_code == SIP_NOT_ACCEPTABLE_HERE){
			dbg("message not acceptable by callee.");
		}
	  	break;
	  case EXOSIP_MESSAGE_SERVERFAILURE:
	  	dbg("message server fail.");
	  	break;
	  case EXOSIP_MESSAGE_GLOBALFAILURE:
	  	dbg("message global fail.");
	  	break;







	  
	  //subscriber
      case EXOSIP_SUBSCRIPTION_NOANSWER:
	  	break;
	  case EXOSIP_SUBSCRIPTION_PROCEEDING:
	  	break;
	  case EXOSIP_SUBSCRIPTION_ANSWERED:
	  	break;
	  case EXOSIP_SUBSCRIPTION_REDIRECTED:
	  	break;
	  case EXOSIP_SUBSCRIPTION_REQUESTFAILURE:
	  	break;
	  case EXOSIP_SUBSCRIPTION_SERVERFAILURE:
	  	break;
	  case EXOSIP_SUBSCRIPTION_GLOBALFAILURE:
	  	break;
	  case EXOSIP_IN_SUBSCRIPTION_NEW:
	  	break;
		
	  //notification
	  case EXOSIP_NOTIFICATION_NOANSWER:
	  	break;
  	  case EXOSIP_NOTIFICATION_PROCEEDING:
	  	break;
  	  case EXOSIP_NOTIFICATION_ANSWERED:
	  	break;
  	  case EXOSIP_NOTIFICATION_REDIRECTED:
	  	break;
  	  case EXOSIP_NOTIFICATION_REQUESTFAILURE:
	  	break;
  	  case EXOSIP_NOTIFICATION_SERVERFAILURE:
	  	break;
  	  case EXOSIP_NOTIFICATION_GLOBALFAILURE:
	  	break;
      default:
        syslog_wrapper (LOG_DEBUG, "recieved unknown eXosip event (type, did, cid) = (%d, %d, %d)", event->type, event->did, event->cid);

    }
    eXosip_event_free (event);
  }//end while 1

  return 0;
}

