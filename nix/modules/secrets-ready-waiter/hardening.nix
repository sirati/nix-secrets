# Sandbox shared by the secrets waiters and the waiting reporter: an
# unprivileged dynamic user that only talks AF_UNIX (sd_notify, D-Bus).
{
  DynamicUser = true;
  CapabilityBoundingSet = "";
  DevicePolicy = "closed";
  LockPersonality = true;
  MemoryDenyWriteExecute = true;
  NoNewPrivileges = true;
  PrivateDevices = true;
  PrivateMounts = true;
  PrivateTmp = true;
  ProtectClock = true;
  ProtectControlGroups = true;
  ProtectHome = true;
  ProtectHostname = true;
  ProtectKernelLogs = true;
  ProtectKernelModules = true;
  ProtectKernelTunables = true;
  ProtectProc = "invisible";
  ProtectSystem = "strict";
  RemoveIPC = true;
  RestrictAddressFamilies = [ "AF_UNIX" ];
  RestrictNamespaces = true;
  RestrictRealtime = true;
  RestrictSUIDSGID = true;
  SystemCallArchitectures = "native";
  SystemCallFilter = [
    "@system-service"
    "~@privileged"
    "~@resources"
  ];
  UMask = "0077";
}
