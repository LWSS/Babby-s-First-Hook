#include <windows.h>
#include <stdint.h>

typedef unsigned __int64 QWORD; // my windows doesn't have this for some reason. 

/* Simple x86 unconditional jmp */
bool jmpHook( void *toHook, void *ourFunc, int len )
{
	if( len < 5 ) { // Jmp = 1 byte, addr = 4 byte
		return false; // can't hook 
	}
	DWORD curProtection;
	if( VirtualProtect( toHook, len, PAGE_EXECUTE_READWRITE, &curProtection ) == 0 ){ // Change memory permissions for the process so we can overwrite some memory 
		return false;
	}

	memset( toHook, 0x90, len ); // NOP region.

	DWORD relativeAddress = ((DWORD)ourFunc - (DWORD)toHook) - 5; // jump to our function from wherever we're at currently ( opcode takes a 4 byte relative )

	*(BYTE*)toHook = 0xE9; // add jmp opcode to start
	*(DWORD*)((DWORD)toHook + 1 ) = relativeAddress; // 4 byte relative offset 

	if( VirtualProtect( toHook, len, curProtection, &curProtection ) == 0 ){ // Restore the original memory permissions.
		return false;
	}

	return true;
}
/* x64 Big Jump  */
bool jmpHook64Big( void *toHook, void *ourFunc, int len )
{
	return false; //unimplemented :^)
}
/* x64 Small Jump  */
bool jmpHook64Small( void *toHook, void *ourFunc, int len )
{
	//uint8_t *origOps = new uint8_t[len];
	//memcpy( origOps, toHook, len ); // save original opcodes

	uint8_t jmp[6];
	jmp[0] = 0xFF; // jmp 
	jmp[1] = 0x25; // set MODRM byte - use disp32
	*(uint32_t*)( jmp+2 ) = ((DWORD)ourFunc - (DWORD)toHook - 6);

	DWORD curProtection; 
	if( VirtualProtect( toHook, len, PAGE_EXECUTE_READWRITE, &curProtection ) == 0 ){
		return false;
	}
	memset( toHook, 0x90, len ); // NOP region
	memcpy( toHook, jmp, sizeof( jmp ) );
	
	if( VirtualProtect( toHook, len, curProtection, &curProtection ) == 0 ){
		return false;
	}

	// delete[] origOps;
	return true;
}
/* x64 unconditional jmp */
bool jmpHook64( void *toHook, void *ourFunc, int len )
{
	if( len < 6 ){
		return false; // cannot hook with less than 6 bytes on x64
	}
	if( ((QWORD)ourFunc - (QWORD)toHook - 6 > 0x7FFFFFFE ) ) {
		return jmpHook64Big( toHook, ourFunc, len );
	} else {
		if( len < 14 ){
			return false; //can't setup call/retn 
		}
		return jmpHook64Small( toHook, ourFunc, len );
	}
}

DWORD jmpBackAddy;
/* Asm to execute at the hookAddress */
void __declspec(naked) ourFunc()
{
	__asm{
		// ...
		jmp [jmpBackAddy]
	}
}

DWORD WINAPI MainThread( LPVOID param ){
	int hookLength = 0; // number of bytes to override, be sure not to split instructions.
	DWORD hookAddress = 0x00000000; // address at which to start
	jmpBackAddy = hookAddress + hookLength;

	if( jmpHook( (void*)hookAddress, ourFunc, hookLength ) == false ){
		// hooking failed
	}
	for( ;; ) {
		if( GetAsyncKeyState(VK_ESCAPE) ) break;
		Sleep(50);
	}
	FreeLibraryAndExitThread( (HMODULE)param, 0 );

	return 0;
}

BOOL WINAPI DllMain( HINSTANCE hModule, DWORD dwReason, LPVOID lpReserved ){
	switch( dwReason ){
		case DLL_PROCESS_ATTACH:
			CreateThread( 0, 0, MainThread, hModule, 0, 0 );
			break;
	}
	return true;
}