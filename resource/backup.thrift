enum KeyBackupRequestTriggerReason {
    UNKNOWN = 0,
    BACKGROUND_NEW_KEY_CREATED = 1,
    BACKGROUND_PERIODICAL_VERIFICATION = 2,
    FOREGROUND_NEW_PIN_REGISTERED = 3,
    FOREGROUND_VERIFICATION = 4
}

struct CreateE2EEKeyBackupRequest {
    1: binary blobHeader;
    2: binary blobPayload;
    3: KeyBackupRequestTriggerReason reason;
}

struct DeleteE2EEKeyBackupRequest {}

struct RestoreE2EEKeyBackupRequest {
    1: binary restoreClaim;
}

struct RestoreE2EEKeyBackupResponse {
    1: binary recoveryKey;
    2: binary blobPayload;
}

struct GetE2EEKeyBackupInfoRequest {}

struct GetE2EEKeyBackupInfoResponse {
    1: binary blobHeaderHash;
    2: binary blobPayloadHash;
    3: set<i32> missingKeyIds;
    4: i64 startTimeMillis;
    5: i64 endTimeMillis;
}

struct GetE2EEKeyBackupCertificatesRequest {}

struct GetE2EEKeyBackupCertificatesResponse {
    1: list<string> urlHashList;
}

enum KeyBackupErrorCode {
    ILLEGAL_ARGUMENT = 0,
    AUTHENTICATION_FAILED = 1,
    INTERNAL_ERROR = 2,
    RESTORE_KEY_FIRST = 3,
    NO_BACKUP = 4,
    INVALID_PIN = 6,
    PERMANENTLY_LOCKED = 7,
    INVALID_PASSWORD = 8,
    MASTER_KEY_CONFLICT = 9
}

exception E2EEKeyBackupException {
    1: KeyBackupErrorCode code;
    2: string reason;
    3: map<string, string> parameterMap;
}

service E2EEKeyBackupService {
    void createE2EEKeyBackupEnforced(
        2: CreateE2EEKeyBackupRequest request) throws(1: E2EEKeyBackupException e);

    void deleteE2EEKeyBackup(
        2: DeleteE2EEKeyBackupRequest request) throws(1: E2EEKeyBackupException e);

    RestoreE2EEKeyBackupResponse restoreE2EEKeyBackup(
        2: RestoreE2EEKeyBackupRequest request) throws(1: E2EEKeyBackupException e);

    GetE2EEKeyBackupInfoResponse getE2EEKeyBackupInfo(
        2: GetE2EEKeyBackupInfoRequest request) throws(1: E2EEKeyBackupException e);

    GetE2EEKeyBackupCertificatesResponse getE2EEKeyBackupCertificates(
        2: GetE2EEKeyBackupCertificatesRequest request
    ) throws(1: E2EEKeyBackupException e);
}