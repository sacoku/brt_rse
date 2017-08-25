#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <malloc.h>
#include <json.h>
#include "common.h"

/**
 * "rse-config"
 * {
 *		"rseid" : "0x0401010102030102",
 *		"keytable" : "/jffs/brt/lgh.ktv",
 *		"sec-policy" : "/jffs/brt/sep.sec"
 *		"log-file" : "/jffs/brt/zlog.cfg" 
 *		"map-ver" : "",
 *		"obe-ctrl" : "",
 *		"intf-name" : "br0"
 *		"ppc-port" : 30000
 * }
 
 **/

int load_config(char *cfg_file)
{
	FILE 			*fp;
	int				ret;
	char			buff[1024 * 5];
	json_object		*jroot, *jobj;
	
	fp = fopen(cfg_file, "r");
	if(!fp)
	{
		fprintf(stderr, "%s file open failed\n", cfg_file);
		return RESULT_FAIL;
	}

	ret = fread(buff, 1, 1024 * 5, fp);
	if(ret <= 0)
	{
		fprintf(stderr, "file read failed[len:%d]\n", ret);
		goto bad_load;
	}

	jroot = json_tokener_parse(buff);
	if(!jroot)
	{
		fprintf(stderr, "parse failed\n");
		goto bad_load;
	}

	jroot = json_object_object_get(jroot, "rse-config");
	if(!jroot)
	{
		fprintf(stderr, "get jroot failed\n");
		goto bad_load;
	}

	jobj = json_object_object_get(jroot, "rseid");
	if(!jobj)
	{
		fprintf(stderr, "get jroot failed\n");
		goto bad_load;
	}
	str2hex(json_object_get_string(jobj), (uint8_t*)rse_cb->cfg.rse_id);

	jobj = json_object_object_get(jroot, "keytable");
	if(!jobj)
	{
		fprintf(stderr, "get jroot failed\n");
		goto bad_load;
	}
	strcpy(rse_cb->cfg.kt_file, json_object_get_string(jobj));

	jobj = json_object_object_get(jroot, "sec-policy");
	if(!jobj)
	{
		fprintf(stderr, "get jroot failed\n");
		goto bad_load;
	}
	strcpy(rse_cb->cfg.se_file, json_object_get_string(jobj));

	jobj = json_object_object_get(jroot, "log-file");
	if(!jobj)
	{
		fprintf(stderr, "get jroot failed\n");
		goto bad_load;
	}
	strcpy(rse_cb->cfg.log_file, json_object_get_string(jobj));

	jobj = json_object_object_get(jroot, "intf-name");
	if(!jobj)
	{
		fprintf(stderr, "get jroot failed\n");
		goto bad_load;
	}
	strcpy(rse_cb->cfg.intf_name, json_object_get_string(jobj));

	
	jobj = json_object_object_get(jroot, "ppc-port");
	if(!jobj)
	{
		fprintf(stderr, "get jroot failed\n");
		goto bad_load;
	}
	rse_cb->cfg.ppc_port = json_object_get_int(jobj);

	return RESULT_OK;
	
bad_load:
	return RESULT_FAIL;
}
