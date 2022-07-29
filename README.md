# AdvancedAPKLeaks
AdvancedAPKLeaks to scan Android APKs and search for secrets.

# Deployment
## Basic Steps
There are some basic requirements for successful deployment of the service:

1. Set up a Linux or Windows host with docker and docker-compose installed
2. Create necessary enviornment variable files, see [this section for details](#production-environment-variables).
   1. If necessary, modify config files in `config.cfg`
3. Build the docker image with `docker-compose build`
4. Create the external network with `docker network apk-scanner-net`
5. Initialize the application with `docker-compose run --rm apkscanner-cli init`. The mountpoint is created and the APK files, that should be scanned, can now be copied to the specified APK file folder.
6. Start the application with `docker-compose up -d`. The stored APKs are now scanned.
7. (If you want to start the application manually use `docker-compose run --rm apkscanner-cli start-scan`)

## Production Environment Variables
Some sensitive config values, such as passwords, have to be set using environment variables. Docker containers in production mode use one files for that:

`resources/.env`

    MONGODB_PORT=27018
    MONGODB_DATA_DIR=./local/data/dir
    USER_ID=1000
    USER_NAME=ubuntu
    GROUP_ID=1000
    GROUP_NAME=ubuntu
    REPO_USER=is
    REPO_PASSWORD=<Repository password for is repo>
    BASE_PATH=.
    MONGO_INITDB_DATABASE=apk_scanner
    MONGO_INITDB_ROOT_USERNAME=<db_user>
    MONGO_INITDB_ROOT_PASSWORD=<db_password>
    FIRMWAREDROID_DB_STRING=<connection string to firmwaredroid db>
    FIRMWAREDROID_COOKIE=<cookie for the firmwaredroid api>

# Config
The configuration of the application is managed by the `config.cfg` file. The file contains the following setting options

    [db]
    db_name = <DB name for the scan results>
    db_extracted_secrets = <DB name for the extracted secrets>
    db_data_analysis = <DB name for the data_analysis db>
    collection_advanced_apkleaks = <Collection name for the scan results>
    host = <Name of mongodb instance>
    port = <Port of mongodb instance>

    [AdvancedAPKLeaks]:
    restriction_mode = <Regularization mode, there are four levels: NONE, LOW, MEDIUM, HIGH>
    mountpoint = <Mountpoint for the application. DEFAULT: /apks> 
    apk_folder = <Folder where the apks are stored (must be in the mountpoint). DEFAULT: /apk_files> 
    results_folder = <Folder where the results are stored (must be in the mountpoint). DEFAULT: /results> 
    source_folder = <Folder where the decompiled sources are stored (must be in the mountpoint). DEFAULT: /sources>
    plot_folder = <Folder where the generated graphs are stored (must be in the mountpoint). DEFAULT: /plots>
    verbose = <Determines whether the decompiled source files should be kept or deleted>
    wipe_resources = <Deletes already existing source files and decompiles the APK again>
    include_firmware_droid_data = <Determines if the FirmwareDroid dataset should be scanned and compared (requires DB connection string and a cookie for the API)>

    [FirmwareDroid]
    api_url = <Base url to the FirmwareDroid API>
    db_extracted_secrets = <DB for the extracted data from the FirmwareDroid DB>