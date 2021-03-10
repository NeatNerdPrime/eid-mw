
/* ****************************************************************************

 * eID Middleware Project.
 * Copyright (C) 2008-2009 FedICT.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version
 * 3.0 as published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, see
 * http://www.gnu.org/licenses/.

**************************************************************************** */
	 

/********************************************************************************
*
*	dlgs.cpp
*
********************************************************************************/ 
#include <stdlib.h>
#include <signal.h>
#include "errno.h"
	
#include "mw_util.h"
#include "dialogs.h"
#include "langutil.h"
	
#include "sharedmem.h"
#include <map>
	
#include "log.h"
#include "util.h"
#include "mwexception.h"
#include "eiderrors.h"
#include "config.h"
	
#include <CoreFoundation/CFNumber.h>
#include <CoreFoundation/CFUserNotification.h>
	









	/************************
	*       DIALOGS
	************************/ 
	
//TODO: Add Keypad possibility in DlgAskPin(s)                                      
	DLGS_EXPORT DlgRet eIDMW::DlgAskPin(DlgPinOperation operation,
					    
					    const wchar_t * wsPinName,
					    
					    wchar_t * wsPin,
					    unsigned long ulPinBufferLen) 
{
	
	
	
	
	
	{
		
		
			// creating the shared memory segment
			// attach oData 
			oShMemory.Attach(sizeof(DlgAskPINArguments),
					 csReadableFilePath.c_str(),
					 (void **) &oData);
		
			// collect the arguments into the struct placed 
			// on the shared memory segment
			oData->operation = operation;
		
		
			  sizeof(oData->pinName) / sizeof(wchar_t),
			  wsPinName);
		
		
			  wsPin);
		
		
		
		{
			
		
		
			// detach from the segment
			oShMemory.Detach(oData);
		
			// delete the random file
			DeleteFile(csReadableFilePath.c_str());
	
	
	{
		
			// detach from the segment
			oShMemory.Detach(oData);
		
			// delete the random file
			DeleteFile(csReadableFilePath.c_str());
		
	
	



					    
					    const wchar_t * wsPinName,
					    
					    wchar_t * wsPin1,
					    unsigned long ulPin1BufferLen,
					    
					    wchar_t * wsPin2,
					    unsigned long ulPin2BufferLen) 
{
	
	
	
	
	
	{
		
		
			// creating the shared memory segment
			// attach oData 
			oShMemory.Attach(sizeof(DlgAskPINsArguments),
					 csReadableFilePath.c_str(),
					 (void **) &oData);
		
			// collect the arguments into the struct placed 
			// on the shared memory segment
			oData->operation = operation;
		
		
			  sizeof(oData->pinName) / sizeof(wchar_t),
			  wsPinName);
		
		
		
			  wsPin1);
		
			  wsPin2);
		
		
		
		{
			
			
		
		
			// detach from the segment
			oShMemory.Detach(oData);
		
			// delete the random file
			DeleteFile(csReadableFilePath.c_str());
	
	catch( ...)
	{
		
			// detach from the segment
			oShMemory.Detach(oData);
		
			// delete the random file
			DeleteFile(csReadableFilePath.c_str());
		
	
	



					   const wchar_t * wsPinName,
					   
{
	
	
	
	
	
	{
		
		
			// creating the shared memory segment
			// attach oData 
			
					  csReadableFilePath.c_str(),
					  (void **) &oData);
		
			// collect the arguments into the struct placed 
			// on the shared memory segment
			oData->usage = usage;
		
			  sizeof(oData->pinName) / sizeof(wchar_t),
			  wsPinName);
		
		
		
		
			// detach from the segment
			oShMemory.Detach(oData);
		
			// delete the random file
			DeleteFile(csReadableFilePath.c_str());
	
	catch( ...)
	{
		
			// detach from the segment
			oShMemory.Detach(oData);
		
			// delete the random file
			DeleteFile(csReadableFilePath.c_str());
		
	
	



						  
						  DlgPinUsage usage,
						  const wchar_t * wsPinName,
						  
						  
						  **puserNotificationRef) 
{
	
	
	
	
	

	
	
	
	

	
	
		{ kCFUserNotificationAlertHeaderKey,
	
	};
	
		
	{
		
		
	}
	
	else
		
	{
		
		
	
	
	
	
		CFStringCreateWithBytes(
					
					
					
	
	
	
		CFStringCreateWithBytes(
					
					
					
	
	
	
	};
	
		CFDictionaryCreate(0, keys, values,
				   
				   
	
							  30,	//CFTimeInterval timeout,
							  optionFlags,	//CFOptionFlags flags,
							  &error,	//SInt32 *error,
							  parameters);	//CFDictionaryRef dictionary
	
	
	
	



DlgClosePinpadInfo(void *theUserNotificationRef) 
{
	
	
		(CFUserNotificationRef) theUserNotificationRef;
	
	

{
	
		// check if we have this handle
		for (std::map < unsigned long,
		     DlgRunningProc * >::iterator pIt =
		     
		     pIt != dlgPinPadInfoCollector.end(); ++pIt)
	{
		
			// check if the process is still running
			// and send SIGTERM if so
			if (!kill(pIt->second->tRunningProcess, 0))
		{
			
				 L"  eIDMW::DlgCloseAllPinpadInfo :  sending kill signal to process %d\n",
				 
			
			{
				
				       L"  eIDMW::DlgCloseAllPinpadInfo sent signal SIGINT to proc %d : %s ",
				       
				       strerror(errno));
				
			
		
		{
			
			       L"  eIDMW::DlgCloseAllPinpadInfo sent signal 0 to proc %d : %s ",
			       
			       strerror(errno));
			
		
		
			// delete the random file
			DeleteFile(pIt->second->csRandomFilename.c_str());
		
		
		
			// memory is cleaned up in the child process
	}
	
		// delete the map 
		dlgPinPadInfoCollector.clear();



						 
						 const wchar_t * csMesg,
						 
						 unsigned char ulEnterButton,
						 
						 ulCancelButton) 
{
	
	
	
	
	
	{
		
		
				    csReadableFilePath.c_str(),
				    (void **) &oData);
		
		
			
		{
			
							GetMessageFromID
							(messageID));
			
				  sizeof(oData->mesg) / sizeof(wchar_t),
				  translatedMessage.c_str());
		
		
		else
			
		{
			
				  sizeof(oData->mesg) / sizeof(wchar_t),
				  csMesg);
		
		
		
		oData->CancelButton = ulCancelButton;
		
				csReadableFilePath.c_str());
		
		
			// detach from the segment
			oShMemory.Detach(oData);
		
			// delete the random file
			DeleteFile(csReadableFilePath.c_str());
	
	catch( ...)
	{
		
			// detach from the segment
			oShMemory.Detach(oData);
		
			// delete the random file
			DeleteFile(csReadableFilePath.c_str());
		
	
	



					      const wchar_t * wsReaderName,
					      
					      int *piForAllOperations) 
{
	
	
	
	
	
	{
		
		
			// attach to the segment and get a pointer
			oShMemory.Attach(sizeof(DlgAskAccessArguments),
					 csReadableFilePath.c_str(),
					 (void **) &oData);
		
			    sizeof(oData->appPath) / sizeof(wchar_t),
			    wsAppPath);
		
			  sizeof(oData->readerName) / sizeof(wchar_t),
			  wsReaderName);
		
		
		
		
		
			*piForAllOperations = oData->forAllOperations;
		
			// detach from the segment
			oShMemory.Detach(oData);
		
			// delete the random file
			DeleteFile(csReadableFilePath.c_str());
	
	catch( ...)
	{
		
			// detach from the segment
			oShMemory.Detach(oData);
		
			// delete the random file
			DeleteFile(csReadableFilePath.c_str());
		
	
	




/***************************
 *       Helper Functions
 ***************************/ 

{
	
		return;
	
	
	



{
	
	
		// start the filename with a dot, so that it is not visible with a normal 'ls'
		std::string randomFileName = "/tmp/.file_";
	

	
	
	



{
	
	
		// create this file
	char csCommand[100];

	
	
	{
		
			// If this lib is used by acroread, all system() calls
			// seems to return -1 for some reason, even if the
			// call was successfull.
			FILE * test = fopen(csFilePath.c_str(), "r");
		
		{
			
			
			
			       L"  eIDMW::CreateRandomFile %s : %s (%d)",
			       
		
		
		else
		{
			
			       L"  eIDMW::CreateRandomFile %s : %s (%d)",
			       
			
		
	
	



{
	

	
	
	{
		
		       L"  eIDMW::DeleteFile %s : %s ", 
		       strerror(errno));
		
			//throw CMWEXCEPTION(EIDMW_ERR_SYSTEM);
	}



			    
{
	

	
		 csFilename);
	

	
	{
		
		       L"  eIDMW::CallQTServer %i %s : %s ", 
		       csFilename, strerror(errno));
		
			
	
	


