#ifndef EID_VWR_BACKEND_H
#define EID_VWR_BACKEND_H

#ifdef WIN32
#define DllExport   __declspec( dllexport ) 
#else
#define DllExport
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "oslayer.h"

DllExport void be_setcallbacks(struct eid_vwr_ui_callbacks* cb_);
DllExport int eid_vwr_set_cbfuncs(		void(*newsrc)(enum eid_vwr_source source), // data source has changed.
	void(*newstringdata)(const EID_CHAR* label, const EID_CHAR* data), // new string data to be displayed in UI.
	void(*newbindata)(const EID_CHAR* label, const unsigned char* data, int datalen), // new binary data to be displayed in UI.
	void(*log)(enum eid_vwr_loglevel loglevel, const EID_CHAR* line), // log a string at the given level.
	//void(*logv)(enum eid_vwr_loglevel loglevel, const char* line, va_list ap), // log a string using varargs. Note: a UI needs to implement only one of log() or logv(); the backend will use whichever is implemented.
	void(*newstate)(enum eid_vwr_states states), // issued at state machine transition
	void(*pinop_result)(enum eid_vwr_pinops pinops, enum eid_vwr_result result) // issued when a PIN operation finished.
	);

void be_newsource(enum eid_vwr_source which);
void be_log(enum eid_vwr_loglevel, const EID_CHAR* line, ...);
void be_newstate(enum eid_vwr_states s);
void be_newstringdata(const EID_CHAR* label, const EID_CHAR* data);
void be_newbindata(const EID_CHAR* label, const unsigned char* data, int datalen);
void be_pinresult(enum eid_vwr_pinops, enum eid_vwr_result);

#ifdef __cplusplus
}
#endif

#endif