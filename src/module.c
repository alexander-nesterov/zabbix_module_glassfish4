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

static int zbx_module_glassfish_discovery_application(AGENT_REQUEST *request, AGENT_RESULT *result);
static int zbx_module_glassfish_discovery_pool(AGENT_REQUEST *request, AGENT_RESULT *result);
static int zbx_module_glassfish_ping_connection_pool(AGENT_REQUEST *request, AGENT_RESULT *result);
static int zbx_module_glassfish_resource(AGENT_REQUEST *request, AGENT_RESULT *result);
static int zbx_module_glassfish_resource_json(AGENT_REQUEST *request, AGENT_RESULT *result);
static int zbx_module_glassfish_http_service(AGENT_REQUEST *request, AGENT_RESULT *result);
static int zbx_module_glassfish_http_service_json(AGENT_REQUEST *request, AGENT_RESULT *result);
static int zbx_module_glassfish_application(AGENT_REQUEST *request, AGENT_RESULT *result);
static int zbx_module_glassfish_application_json(AGENT_REQUEST *request, AGENT_RESULT *result);

static ZBX_METRIC keys[] =
/* 			  KEY                          FLAG                   FUNCTION                   TEST PARAMETERS */
{
    {"glassfish.discovery.application",	CF_HAVEPARAMS, zbx_module_glassfish_discovery_application,	NULL},
    {"glassfish.discovery.pool",	CF_HAVEPARAMS, zbx_module_glassfish_discovery_pool,		NULL},
    {"glassfish.ping.connection.pool",	CF_HAVEPARAMS, zbx_module_glassfish_ping_connection_pool,	NULL},
    {"glassfish.resource",   		CF_HAVEPARAMS, zbx_module_glassfish_resource,  			NULL},
    {"glassfish.resource.json",   	CF_HAVEPARAMS, zbx_module_glassfish_resource_json,  		NULL},
    {"glassfish.http.service",   	CF_HAVEPARAMS, zbx_module_glassfish_http_service,  		NULL},
    {"glassfish.http.service.json",	CF_HAVEPARAMS, zbx_module_glassfish_http_service_json,		NULL},
    {"glassfish.application",   	CF_HAVEPARAMS, zbx_module_glassfish_application,  		NULL},
    {"glassfish.application.json",  	CF_HAVEPARAMS, zbx_module_glassfish_application_json,  		NULL},
    {NULL}
};

/******************************************************************************
*                                                                            *
* Function: zbx_module_api_version                                           *
*                                                                            *
* Purpose: returns version number of the module interface                    *
*                                                                            *
* Return value: ZBX_MODULE_API_VERSION - version of module.h module is       *
*               compiled with, in order to load module successfully Zabbix   *
*               MUST be compiled with the same version of this header file   *
*                                                                            *
******************************************************************************/
int zbx_module_api_version(void)	
{
    return ZBX_MODULE_API_VERSION;
}
	
/******************************************************************************
*                                                                            *
* Function: zbx_module_init                                                  *	
*                                                                            *	
* Purpose: the function is called on agent startup                           *	
*          It should be used to call any initialization routines             *	
*                                                                            *	
* Return value: ZBX_MODULE_OK - success                                      *	
*               ZBX_MODULE_FAIL - module initialization failed               *	
*                                                                            *	
* Comment: the module won't be loaded in case of ZBX_MODULE_FAIL             *
*                                                                            *	
******************************************************************************/
int zbx_module_init(void)
{
    srand(time(NULL));
	
    zabbix_log(LOG_LEVEL_INFORMATION, 
	       "Module: %s - openssl: '%s', libcurl: %s, regex: %s (%s:%d)", 
	       MODULE_NAME, OPENSSL_VERSION_TEXT, "", "" , __FILE__, __LINE__ );
	
    return ZBX_MODULE_OK;
}
	
/******************************************************************************
*                                                                            *
* Function: zbx_module_uninit                                                *
*                                                                            *
* Purpose: the function is called on agent shutdown                          *
*          It should be used to cleanup used resources if there are any      *
*                                                                            *
* Return value: ZBX_MODULE_OK - success                                      *
*               ZBX_MODULE_FAIL - function failed                            *
*                                                                            *
******************************************************************************/
int zbx_module_uninit(void)
{
    return ZBX_MODULE_OK;
}
	
/******************************************************************************
*                                                                            *
* Function: zbx_module_item_list                                             *
*                                                                            *
* Purpose: returns list of item keys supported by the module                 *
*                                                                            *
* Return value: list of item keys                                            *
*                                                                            *
******************************************************************************/
ZBX_METRIC *zbx_module_item_list()
{
    return keys;
}

/*
*/
static int zbx_module_glassfish_discovery_application(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    return SYSINFO_RET_OK;
}

/*
*/
static int zbx_module_glassfish_discovery_pool(AGENT_REQUEST *request, AGENT_RESULT *result)
{			   
    return SYSINFO_RET_OK;
}

/*
glassfish.ping.connection.pool["https://{HOST.CONN}", 8888, "pool", "exit_code.:.(\w+).,", "user", "password"]
*/
static int zbx_module_glassfish_ping_connection_pool(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    char *data;
    const char *dataRes;
    int res;
    int value;
	
    zabbix_log(LOG_LEVEL_DEBUG, "Module: %s - param num: %d (%s:%d)", MODULE_NAME, request->nparam, __FILE__, __LINE__ );
	
    if (6 != request->nparam)
    {
        SET_MSG_RESULT(result, strdup("Invalid number of parameters"));
	zabbix_log(LOG_LEVEL_DEBUG, "Error in module: %s - invalid number of parameters (%s:%d)", MODULE_NAME, __FILE__, __LINE__ );
	return SYSINFO_RET_FAIL;
    }
	
    res = curl_init();
    
    if (res != CURLE_OK)
    {
	SET_MSG_RESULT(result, strdup("Error initilization libcurl"));
	zabbix_log(LOG_LEVEL_DEBUG, "Error in module: %s - could not initilization libcurl (%s:%d)", MODULE_NAME, __FILE__, __LINE__ );
	return SYSINFO_RET_FAIL;
    }
	
    char *host = get_rparam(request, 0);
    char *port = get_rparam(request, 1);
    char *namePool = get_rparam(request, 2);
    char *regex = get_rparam(request, 3);
    char *user = get_rparam(request, 4);
    char *password = get_rparam(request, 5);
	
    char fullURL[URL_LENGTH];
    zbx_snprintf(fullURL, URL_LENGTH, "%s:%s/%s/?appname=&id=%s&modulename=&targetName=&__remove_empty_entries__=true", host, port, GLASSFISH_PING_CONNECTION_POOL, namePool);
	
    curl_set_opt(fullURL, user, password);
	
    data = get_data();
    zabbix_log(LOG_LEVEL_DEBUG, "Module: %s - raw data: %s (%s:%d)", MODULE_NAME, data, __FILE__, __LINE__ );
	
    dataRes = parse_data(data, regex);
    zabbix_log(LOG_LEVEL_DEBUG, "Module: %s - parse data: %s (%s:%d)", MODULE_NAME, dataRes, __FILE__, __LINE__ );
	
    zbx_free(data);
	
    if (dataRes == NULL)
    {
        SET_MSG_RESULT(result, strdup("Result is empty"));
	zabbix_log(LOG_LEVEL_DEBUG, "Error in module: %s - result is empty (%s:%d)", MODULE_NAME, __FILE__, __LINE__ );
	return SYSINFO_RET_FAIL;
    }
	
    if (strcmp(dataRes, "SUCCESS") == 0)
        value = 1;
    else
	value = 0;
	
    SET_UI64_RESULT(result, value);
    return SYSINFO_RET_OK;
}

/*
glassfish.resource["https://{HOST.CONN}", 8888, "resource", "averageconnwaittime", "count.:(\d+),", "user", "password"]
*/
static int zbx_module_glassfish_resource(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    char *data;
    const char *dataRes;
    int res;
    int value;
	
    zabbix_log(LOG_LEVEL_DEBUG, "Module: %s - param num: %d (%s:%d)", MODULE_NAME, request->nparam, __FILE__, __LINE__ );
	
    if (7 != request->nparam)
    {
        SET_MSG_RESULT(result, strdup("Invalid number of parameters"));
	zabbix_log(LOG_LEVEL_DEBUG, "Error in module: %s - invalid number of parameters (%s:%d)", MODULE_NAME, __FILE__, __LINE__ );
	return SYSINFO_RET_FAIL;
    }
	
    res = curl_init();
	
    if (res != CURLE_OK)
    {
	SET_MSG_RESULT(result, strdup("Error initilization libcurl"));
	zabbix_log(LOG_LEVEL_DEBUG, "Error in module: %s - could not initilization libcurl (%s:%d)", MODULE_NAME, __FILE__, __LINE__ );
	return SYSINFO_RET_FAIL;
    }
	
    char *host = get_rparam(request, 0);
    char *port = get_rparam(request, 1);
    char *nameResource = get_rparam(request, 2);
    char *resourceKey = get_rparam(request, 3);
    char *regex = get_rparam(request, 4);
    char *user = get_rparam(request, 5);
    char *password = get_rparam(request, 6);
	
    char fullURL[URL_LENGTH];
    zbx_snprintf(fullURL, URL_LENGTH, "%s:%s/%s/%s/%s", host, port, GLASSFISH_RESOURCE, nameResource, resourceKey);
	
    curl_set_opt(fullURL, user, password);
	
    data = get_data();
    zabbix_log(LOG_LEVEL_DEBUG, "Module: %s - raw data: %s (%s:%d)", MODULE_NAME, data, __FILE__, __LINE__ );
	
    dataRes = parse_data(data, regex);
    zabbix_log(LOG_LEVEL_DEBUG, "Module: %s - parse data: %s (%s:%d)", MODULE_NAME, dataRes, __FILE__, __LINE__ );
	
    zbx_free(data);
	
    if (dataRes == NULL)
    {
        SET_MSG_RESULT(result, strdup("Result is empty"));
	zabbix_log(LOG_LEVEL_DEBUG, "Error in module: %s - result is empty (%s:%d)", MODULE_NAME, __FILE__, __LINE__ );
	return SYSINFO_RET_FAIL;
    }
	
    value = atoi(dataRes);
	
    SET_UI64_RESULT(result, value);
    return SYSINFO_RET_OK;
}

/*
glassfish.resource.json["https://{HOST.CONN}", 8888, "resource", "averageconnwaittime", "user", "password"]
*/
static int zbx_module_glassfish_resource_json(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    char *data;
    int res;
	
    zabbix_log(LOG_LEVEL_DEBUG, "Module: %s - param num: %d (%s:%d)", MODULE_NAME, request->nparam, __FILE__, __LINE__ );
	
    if (6 != request->nparam)
    {
        SET_MSG_RESULT(result, strdup("Invalid number of parameters"));
	zabbix_log(LOG_LEVEL_DEBUG, "Error in module: %s - invalid number of parameters (%s:%d)", MODULE_NAME, __FILE__, __LINE__ );
        return SYSINFO_RET_FAIL;
    }
	
    res = curl_init();
	
    if (res != CURLE_OK)
    {
	SET_MSG_RESULT(result, strdup("Error initilization libcurl"));
	zabbix_log(LOG_LEVEL_DEBUG, "Error in module: %s - could not initilization libcurl (%s:%d)", MODULE_NAME, __FILE__, __LINE__ );
	return SYSINFO_RET_FAIL;
    }
	
    char *host = get_rparam(request, 0);
    char *port = get_rparam(request, 1);
    char *nameResource = get_rparam(request, 2);
    char *resourceKey = get_rparam(request, 3);
    char *user = get_rparam(request, 4);
    char *password = get_rparam(request, 5);
	
    char fullURL[URL_LENGTH];
    zbx_snprintf(fullURL, URL_LENGTH, "%s:%s/%s/%s/%s", host, port, GLASSFISH_RESOURCE, nameResource, resourceKey);
	
    curl_set_opt(fullURL, user, password);
	
    data = get_data();
    zabbix_log(LOG_LEVEL_DEBUG, "Module: %s - raw data: %s (%s:%d)", MODULE_NAME, data, __FILE__, __LINE__ );
	
    SET_STR_RESULT(result, strdup(data));
	
    zbx_free(data);
	
    return SYSINFO_RET_OK;
}

/*
glassfish.http.service["https://{HOST.CONN}", 8888, "count200", "count.:(\d+),", "user", "password"]
*/
static int zbx_module_glassfish_http_service(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    char *data;
    const char *dataRes;
    int res;
    int value;
	
    zabbix_log(LOG_LEVEL_DEBUG, "Module: %s - param num: %d (%s:%d)", MODULE_NAME, request->nparam, __FILE__, __LINE__ );
	
    if (6 != request->nparam)
    {
        SET_MSG_RESULT(result, strdup("Invalid number of parameters"));
	zabbix_log(LOG_LEVEL_DEBUG, "Error in module: %s - invalid number of parameters (%s:%d)", MODULE_NAME, __FILE__, __LINE__ );
	return SYSINFO_RET_FAIL;
    }
	
    res = curl_init();
	
    if (res != CURLE_OK)
    {
	SET_MSG_RESULT(result, strdup("Error initilization libcurl"));
	zabbix_log(LOG_LEVEL_DEBUG, "Error in module: %s - could not initilization libcurl (%s:%d)", MODULE_NAME, __FILE__, __LINE__ );
	return SYSINFO_RET_FAIL;
    }
	
    char *host = get_rparam(request, 0);
    char *port = get_rparam(request, 1);
    char *requestKey = get_rparam(request, 2);
    char *regex = get_rparam(request, 3);
    char *user = get_rparam(request, 4);
    char *password = get_rparam(request, 5);
	
    char fullURL[URL_LENGTH];
    zbx_snprintf(fullURL, URL_LENGTH, "%s:%s/%s/%s", host, port, GLASSFISH_HTTP_SERVICE, requestKey);
	
    curl_set_opt(fullURL, user, password);
	
    data = get_data();
    zabbix_log(LOG_LEVEL_DEBUG, "Module: %s - raw data: %s (%s:%d)", MODULE_NAME, data, __FILE__, __LINE__ );
	
    dataRes = parse_data(data, regex);
    zabbix_log(LOG_LEVEL_DEBUG, "Module: %s - parse data: %s (%s:%d)", MODULE_NAME, dataRes, __FILE__, __LINE__ );
	
    zbx_free(data);
	
    if (dataRes == NULL)
    {
        SET_MSG_RESULT(result, strdup("Result is empty"));
	zabbix_log(LOG_LEVEL_DEBUG, "Error in module: %s - result is empty (%s:%d)", MODULE_NAME, __FILE__, __LINE__ );
	return SYSINFO_RET_FAIL;
    }
	
    value = atoi(dataRes);
	
    SET_UI64_RESULT(result, value);
    return SYSINFO_RET_OK;
}

/*
glassfish.http.service.json["https://{HOST.CONN}", 8888, "count200", "user", "password"]
*/
static int zbx_module_glassfish_http_service_json(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    char *data;
    int res;
	
    zabbix_log(LOG_LEVEL_DEBUG, "Module: %s - param num: %d (%s:%d)", MODULE_NAME, request->nparam, __FILE__, __LINE__ );
	
    if (5 != request->nparam)
    {
        SET_MSG_RESULT(result, strdup("Invalid number of parameters"));
	zabbix_log(LOG_LEVEL_DEBUG, "Error in module: %s - invalid number of parameters (%s:%d)", MODULE_NAME, __FILE__, __LINE__ );
	return SYSINFO_RET_FAIL;
    }
	
    res = curl_init();
	
    if (res != CURLE_OK)
    {
        SET_MSG_RESULT(result, strdup("Error initilization libcurl"));
	zabbix_log(LOG_LEVEL_DEBUG, "Error in module: %s - could not initilization libcurl (%s:%d)", MODULE_NAME, __FILE__, __LINE__ );
	return SYSINFO_RET_FAIL;
    }
	
    char *host = get_rparam(request, 0);
    char *port = get_rparam(request, 1);
    char *requestKey = get_rparam(request, 2);
    char *user = get_rparam(request, 3);
    char *password = get_rparam(request, 4);
	
    char fullURL[URL_LENGTH];
    zbx_snprintf(fullURL, URL_LENGTH, "%s:%s/%s/%s", host, port, GLASSFISH_HTTP_SERVICE, requestKey);
	
    curl_set_opt(fullURL, user, password);
	
    data = get_data();
    zabbix_log(LOG_LEVEL_DEBUG, "Module: %s - raw data: %s (%s:%d)", MODULE_NAME, data, __FILE__, __LINE__ );
	
    SET_STR_RESULT(result, strdup(data));
	
    zbx_free(data);
	
    return SYSINFO_RET_OK;
}

/*
glassfish.application["https://{HOST.CONN}", 8888, "application", "activesessionscurrent", "current.:(-?\d+),", "user", "password"]
*/
static int zbx_module_glassfish_application(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    char *data;
    const char *dataRes;
    int res;
    int value;
	
    zabbix_log(LOG_LEVEL_DEBUG, "Module: %s - param num: %d (%s:%d)", MODULE_NAME, request->nparam, __FILE__, __LINE__ );
	
    if (7 != request->nparam)
    {
        SET_MSG_RESULT(result, strdup("Invalid number of parameters"));
	zabbix_log(LOG_LEVEL_DEBUG, "Error in module: %s - invalid number of parameters (%s:%d)", MODULE_NAME, __FILE__, __LINE__ );
        return SYSINFO_RET_FAIL;
    }
	
    res = curl_init();
	
    if (res != CURLE_OK)
    {
	SET_MSG_RESULT(result, strdup("Error initilization libcurl"));
	zabbix_log(LOG_LEVEL_DEBUG, "Error in module: %s - could not initilization libcurl (%s:%d)", MODULE_NAME, __FILE__, __LINE__ );
	return SYSINFO_RET_FAIL;
    }
	
    char *host = get_rparam(request, 0);
    char *port = get_rparam(request, 1);
    char *application = get_rparam(request, 2);
    char *requestKey = get_rparam(request, 3);
    char *regex = get_rparam(request, 4);
    char *user = get_rparam(request, 5);
    char *password = get_rparam(request, 6);
	
    char fullURL[URL_LENGTH];
    zbx_snprintf(fullURL, URL_LENGTH, "%s:%s/%s/%s/server/%s", host, port, GLASSFISH_APPLICATION, application, requestKey);
	
    curl_set_opt(fullURL, user, password);
	
    data = get_data();
    zabbix_log(LOG_LEVEL_DEBUG, "Module: %s - raw data: %s (%s:%d)", MODULE_NAME, data, __FILE__, __LINE__ );
	
    dataRes = parse_data(data, regex);
    zabbix_log(LOG_LEVEL_DEBUG, "Module: %s - parse data: %s (%s:%d)", MODULE_NAME, dataRes, __FILE__, __LINE__ );
	
    zbx_free(data);
	
    if (dataRes == NULL)
    {
        SET_MSG_RESULT(result, strdup("Result is empty"));
	zabbix_log(LOG_LEVEL_DEBUG, "Error in module: %s - result is empty (%s:%d)", MODULE_NAME, __FILE__, __LINE__ );
	return SYSINFO_RET_FAIL;
    }
	
    value = atoi(dataRes);
	
    if (value < 0)
        value = 0;
	
    SET_UI64_RESULT(result, value);
    return SYSINFO_RET_OK;
}

/*
glassfish.application.json["https://{HOST.CONN}", 8888, "application", "activesessionscurrent", "user", "password"]
*/
static int zbx_module_glassfish_application_json(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    char *data;
    int res;
	
    zabbix_log(LOG_LEVEL_DEBUG, "Module: %s - param num: %d (%s:%d)", MODULE_NAME, request->nparam, __FILE__, __LINE__ );
	
    if (6 != request->nparam)
    {
        SET_MSG_RESULT(result, strdup("Invalid number of parameters"));
	zabbix_log(LOG_LEVEL_DEBUG, "Error in module: %s - invalid number of parameters (%s:%d)", MODULE_NAME, __FILE__, __LINE__ );
	return SYSINFO_RET_FAIL;
    }
	
    res = curl_init();
	
    if (res != CURLE_OK)
    {
        SET_MSG_RESULT(result, strdup("Error initilization libcurl"));
	zabbix_log(LOG_LEVEL_DEBUG, "Error in module: %s - could not initilization libcurl (%s:%d)", MODULE_NAME, __FILE__, __LINE__ );
	return SYSINFO_RET_FAIL;
    }
	
     char *host = get_rparam(request, 0);
     char *port = get_rparam(request, 1);
     char *application = get_rparam(request, 2);
     char *requestKey = get_rparam(request, 3);
     char *user = get_rparam(request, 4);
     char *password = get_rparam(request, 5);
	
     char fullURL[URL_LENGTH];
     zbx_snprintf(fullURL, URL_LENGTH, "%s:%s/%s/%s/server/%s", host, port, GLASSFISH_APPLICATION, application, requestKey);
	
     curl_set_opt(fullURL, user, password);
	
     data = get_data();
     zabbix_log(LOG_LEVEL_DEBUG, "Module: %s - raw data: %s (%s:%d)", MODULE_NAME, data, __FILE__, __LINE__ );
	
     SET_STR_RESULT(result, strdup(data));
	
     zbx_free(data);
	
     return SYSINFO_RET_OK;
}
