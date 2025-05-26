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

struct GetKeyBackupCertificatesV2Request {}

struct GetKeyBackupCertificatesV2Response {
    1: list<string> urlHashList;
}

struct E2EEMetadata {
    1: i64 e2EEPublicKeyId;
}

enum SingleValueMetadataType {
    INITIAL_BACKUP_ENCRYPTION_KEY = 0
}

struct SingleValueMetadata {
    1: SingleValueMetadataType type;
}

struct LifetimePayloadMetaData {
    1: optional E2EEMetadata e2ee;
    2: optional SingleValueMetadata singleValue;
}

struct LifetimePayloadData {
    1: LifetimePayloadMetaData metadata;
    2: optional binary blobPayload;
}

struct CreateLifetimeKeyBackupRequest {
    1: binary blobHeader;
    2: list<LifetimePayloadData> payloadDataList;
}

struct RestoreLifetimeKeyBackupHeaderRequest {
    1: binary restoreClaim;
}

struct RestoreLifetimeKeyBackupHeaderResponse {
    1: binary recoveryKey;
}

struct ValidateLifetimeKeyBackupHeaderRequest {
    1: i64 masterKeyTimestamp;
    2: optional binary blobHeaderHash;
}

struct AddLifetimeKeyBackupPayloadDataListRequest {
    1: list<LifetimePayloadData> payloadDataList;
}

struct LifetimeBackupFailedPayload {
    1: LifetimePayloadData metadata;
    2: KeyBackupErrorCode errorCode;
}

struct AddLifetimeKeyBackupPayloadDataListResponse {
    1: list<LifetimeBackupFailedPayload> failedPayloads;
}

struct UpdateLifetimeKeyBackupHeaderRequest {
    1: binary blobHeader;
}

struct GetLifetimeKeyBackupPayloadDataListRequest {
    1: list<LifetimePayloadMetaData> metadataList;
}

struct GetLifetimeKeyBackupPayloadDataListResponse {
    1: list<LifetimePayloadData> payloadDataList;
    2: list<LifetimeBackupFailedPayload> failedPayloads;
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
    MASTER_KEY_CONFLICT = 9,
    KEY_BACKUP_HEADER_MISMATCH = 10
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

service E2eeKeyBackupCertificateService {
    GetKeyBackupCertificatesV2Response getKeyBackupCertificatesV2(
        2: GetKeyBackupCertificatesV2Request request
    ) throws(1: E2EEKeyBackupException e);
}

service E2EELifetimeKeyBackupService {
    void createLifetimeKeyBackup(
        2: CreateLifetimeKeyBackupRequest request) throws(1: E2EEKeyBackupException e);

    RestoreLifetimeKeyBackupHeaderResponse restoreLifetimeKeyBackupHeader(
        2: RestoreLifetimeKeyBackupHeaderRequest request
    ) throws(1: E2EEKeyBackupException e);

    void validateLifetimeKeyBackupHeader(
        2: ValidateLifetimeKeyBackupHeaderRequest request
    ) throws(1: E2EEKeyBackupException e);

    AddLifetimeKeyBackupPayloadDataListResponse addLifetimeKeyBackupPayloadDataList(
        2: AddLifetimeKeyBackupPayloadDataListRequest request
    ) throws(1: E2EEKeyBackupException e);

    void updateLifetimeKeyBackupHeader(
        2: UpdateLifetimeKeyBackupHeaderRequest request
    ) throws(1: E2EEKeyBackupException e);

    GetLifetimeKeyBackupPayloadDataListResponse getLifetimeKeyBackupPayloadDataList(
        2: GetLifetimeKeyBackupPayloadDataListRequest request
    ) throws(1: E2EEKeyBackupException e);
}