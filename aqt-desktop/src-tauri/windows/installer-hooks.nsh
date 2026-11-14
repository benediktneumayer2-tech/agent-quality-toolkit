; Hooks of the Windows installer (Tauri's NSIS installer, per-user, see tauri.windows.conf.json).
; They put the folder of the bundled aqt.exe ($INSTDIR\runtime\aqt) on the user's PATH and take it off again
; when the app is uninstalled. The folder holds only aqt.exe, aqt-toolkit.exe, aqtw.exe and _internal\, so no DLL of the
; runtime is found through PATH. PowerShell edits HKCU\Environment\Path and keeps it REG_EXPAND_SZ, so entries
; such as %USERPROFILE%\bin stay as they were; then the running programs are told the environment changed
; (new terminals see the entry; open ones keep their old PATH).

!macro AQT_USER_PATH ACTION
  nsExec::ExecToLog `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$$d='$INSTDIR\runtime\aqt'; $$k=[Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment'); $$p=@([string]$$k.GetValue('Path','','DoNotExpandEnvironmentNames') -split ';' | ? { $$_ -and $$_.TrimEnd('\') -ne $$d }); if ('${ACTION}' -eq 'add') { $$p += $$d }; if ($$p) { $$k.SetValue('Path', ($$p -join ';'), 'ExpandString') } else { $$k.DeleteValue('Path', $$false) }"`
  Pop $R9
  SendMessage 0xFFFF 0x1A 0 "STR:Environment" /TIMEOUT=5000
!macroend

!macro NSIS_HOOK_POSTINSTALL
  !insertmacro AQT_USER_PATH add
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  !insertmacro AQT_USER_PATH remove
!macroend
