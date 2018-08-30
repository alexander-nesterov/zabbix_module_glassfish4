#include "sysinc.h"
#include "module.h"
#include "common.h"
#include "log.h"
#include "pcreposix.h"
#include "zbxregexp.h"
#include "zbxjson.h"
#include <curl/curl.h>
#include <openssl/opensslv.h>
#include <pcre.h>
#include "glassfish.h"

CURL *curl;

struct memoryData
{
	char *memory;
    size_t size;
};

/*
*/
size_t write_data_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size *nmemb;
    struct memoryData *mem = (struct memoryData *)userp;

    mem->memory = realloc(mem->memory, mem->size + realsize + 1);

    if(mem->memory == NULL)
    {
	/* out of memory! */
		zabbix_log(LOG_LEVEL_DEBUG, "Error in module: %s - not enough memory (realloc returned NULL)", MODULE_NAME, __FILE__, __LINE__ );
		return 0;
    }

	memcpy(&(mem->memory[mem->size]), contents, realsize);
  	mem->size += realsize;
  	mem->memory[mem->size] = 0;
  	return realsize;
}

/*
*/
int curl_init(void)
{
	curl_global_init(CURL_GLOBAL_DEFAULT);

	curl = curl_easy_init();

	if(curl)
	{
		return CURLE_OK; /*0*/
  	}
	return CURLE_FAILED_INIT; /*2*/
}

/*
*/
void curl_set_opt(const char *fullURL, const char *user, const char *password)
{
	struct curl_slist *chunk = NULL;

    chunk = curl_slist_append(chunk, HTTP_ACCEPT);

    curl_easy_setopt(curl, CURLOPT_USERAGENT, HTTP_USERAGENT);

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);

    curl_easy_setopt(curl, CURLOPT_VERBOSE, DEBUG);
	
	char auth[AUTH_LENGTH];
	zbx_snprintf(auth, AUTH_LENGTH, "%s:%s", user, password);

	curl_easy_setopt(curl, CURLOPT_USERPWD, auth);

    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, SSL_VERIFYPEER);

    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, SSL_VERIFYHOST);

	zabbix_log(LOG_LEVEL_DEBUG, "Module: %s - fullURL: %s (%s:%d)", MODULE_NAME, fullURL, __FILE__, __LINE__ );
	
    curl_easy_setopt(curl, CURLOPT_URL, fullURL);
}

/*
*/
const char *parse_data(char *data, const char *regex)
{
	const char *errorStr;
    int errorOffset;
    pcre *re;
	int pcreExecRet;
	char **aLineToMatch;
	int subStrVec[30];
	const char *psubStrMatchStr;
	char *dataTmp[] = {data, NULL};
	
	zabbix_log(LOG_LEVEL_DEBUG, "Module: %s - regex: '%s' (%s:%d)", MODULE_NAME, regex, __FILE__, __LINE__ );
	
	re = pcre_compile(regex, 
                      PCRE_MULTILINE,
                      &errorStr,
                      &errorOffset,
                      0);
				  
    if (re == NULL)
    {
		zabbix_log(LOG_LEVEL_DEBUG, "Error in module: %s - could not compile regex: '%s' because %s (%s:%d)", MODULE_NAME, regex, errorStr, __FILE__, __LINE__ );
        exit(-1);
    }
	
	for(aLineToMatch = dataTmp; *aLineToMatch != NULL; aLineToMatch++)
	{
		pcreExecRet = pcre_exec(re,
								NULL,
								*aLineToMatch,
								strlen(*aLineToMatch),
								0,
								0,
								subStrVec,
								30);
		pcre_get_substring(*aLineToMatch, subStrVec, pcreExecRet, REGEX_GROUP, &(psubStrMatchStr));
	}

	pcre_free(re);
	return psubStrMatchStr;
}

/*
*/
char *get_data()
{
	int res;
	struct memoryData chunk;
    chunk.memory = malloc(1);
    chunk.size = 0;
	
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data_callback);
	
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
	
	/*get it*/
	res = curl_easy_perform(curl);
	
	if(res != CURLE_OK)
    {
		zabbix_log(LOG_LEVEL_DEBUG, "Error in module: %s - curl_easy_perform failed (%s:%d)", MODULE_NAME, curl_easy_strerror(res), __FILE__, __LINE__ );
		exit(-1);
    }
	
	curl_easy_cleanup(curl);
	curl_global_cleanup();
	return chunk.memory;
}
