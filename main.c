#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "common.h"

rse_cb_t		*rse_cb;
zlog_category_t	*c;

int main(int argc, char** argv)
{
	int ret;

	rse_cb = malloc(sizeof(rse_cb_t));
	ret = load_config(CFG_FILE_PATH);
	if(ret)
	{
		fprintf(stderr, "config file load failed.\n");
		return ret;
	}

	fprintf(stdout, "config file loading successed.[cfg:%s, log:%s]\n", CFG_FILE_PATH, rse_cb->cfg.log_file);

	INIT_LOGGER(rse_cb->cfg.log_file);
		
	ret = create_wlan(rse_cb->cfg.intf_name, UTIS_PROTOCOL);
	if(ret == RESULT_FAIL)
	{
		PRINT(ERROR, "wlan init failed.\n");
		return ret;
	}
	rse_cb->w_ufd = ret;

	ret = create_wlan(rse_cb->cfg.intf_name, UTIS_BCAST_PROTOCOL);
	if(ret == RESULT_FAIL)
	{
		PRINT(ERROR, "wlan init failed.\n");
		return ret;
	}
	rse_cb->w_bfd = ret;

	PRINT(INFO, "wlan created.\n");

	ret = create_inet_udp(rse_cb->cfg.ppc_port, 1);
	if(ret == RESULT_FAIL)
	{
		PRINT(ERROR, "wlan init failed.\n");
		return ret;
	}
	rse_cb->ifd = ret;

	PRINT(INFO, "inet(ppc) created.\n");
	
	ret = init_keytable(rse_cb->cfg.kt_file);
	if(ret == RESULT_FAIL)
	{
		PRINT(ERROR, "keytable init failed.\n");
		return ret;
	}

	PRINT(INFO, "keytable send to wifi driver complete\n");

	ret = init_secpolicy(rse_cb->cfg.se_file);
	if(ret == RESULT_FAIL)
	{
		PRINT(ERROR, "security policy init failed.\n");
		return ret;
	}

	PRINT(INFO, "security policy send to wifi driver complete\n");

	init_obe();
	utis_obe_handler_init();
	utis_wifi_handler_init();

	PRINT(INFO, "init successed.\n");

	epoll_events(NULL);	

	CLOSE_LOGGER();
	
	return 0;
}
