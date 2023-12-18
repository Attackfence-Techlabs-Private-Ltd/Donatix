#include <stdint.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <ndpi_api.h>
#include <ndpi_main.h>
#include <ndpi_typedefs.h>
#include "ndpi_config.h"
#include <sqlite3.h>

// Function to execute the query and fetch domain names from the database
void fetch_domains_from_db(sqlite3 *db, struct ndpi_detection_module_struct *ndpi_str, int verbose) {
    sqlite3_stmt *stmt;
    int rc;
    const char *update_query = "UPDATE dns_query_data SET isDGA = 1 WHERE qname = ?;";
    char query[] = "SELECT qname FROM dns_query_data WHERE qname != '';";
    int num_detections = 0;
    rc = sqlite3_prepare_v2(db, query, -1, &stmt, 0);
    if (rc == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *hostname = (const char*)sqlite3_column_text(stmt, 0);
            if (ndpi_check_dga_name(ndpi_str, NULL, hostname, 1, 1)) {
                if (verbose)
                    printf("========\n");
                    // Prepare the update statement
                    sqlite3_stmt *stmt_update;
                    rc = sqlite3_prepare_v2(db, update_query, -1, &stmt_update, 0);
                    if (rc != SQLITE_OK) {
                        fprintf(stderr, "Failed to prepare update statement: %s\n", sqlite3_errmsg(db));
                        // Handle the error and return or exit
                    }
                    // Bind the 'hostname' variable to the update statement
                    rc = sqlite3_bind_text(stmt_update, 1, hostname, -1, SQLITE_STATIC);
                    if (rc != SQLITE_OK) {
                        fprintf(stderr, "Failed to bind parameter: %s for hostname: %s\n", sqlite3_errmsg(db), hostname);
                        // Handle the error and return or exit
                    }

                    // Execute the update query
                    rc = sqlite3_step(stmt_update);
                    if (rc != SQLITE_DONE) {
                        fprintf(stderr, "Update failed: %s for hostname: %s\n", sqlite3_errmsg(db), hostname);
                    } else {
                        fprintf(stdout, "Update successful\n");
                    }
                    // Finalize the update statement for the next iteration
                    sqlite3_finalize(stmt_update);
                    num_detections++;
            } else {
                if (verbose)
                    printf("NON DGA %s\n", hostname);
                    printf("------\n");
            }
        }
    } else {
        fprintf(stderr, "Failed to execute the query: %s\n", sqlite3_errmsg(db));
    }
    // Finalize the select statement and close the database
    sqlite3_finalize(stmt);
}


int main(int argc, char **argv) {
    // ... existing code ...
    int verbose = 0;
    NDPI_PROTOCOL_BITMASK all;
    struct ndpi_detection_module_struct *ndpi_str = ndpi_init_detection_module(ndpi_no_prefs);
    assert(ndpi_str != NULL);
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(ndpi_str, &all);
    ndpi_finalize_initialization(ndpi_str);
    sqlite3 *db;
    int rc = sqlite3_open("/opt/attackfence/NDR/tsharkQueryData/networkdata.db", &db);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return rc;
    }

    if (ndpi_get_api_version() != NDPI_API_VERSION) {
        fprintf(stderr, "nDPI Library version mismatch: please make sure this code and the nDPI library are in sync\n");
        return -1;
    }

    // ... existing code ...

    // Call the function to fetch domains from the database and evaluate them
    fetch_domains_from_db(db, ndpi_str, verbose);

    // ... existing code ...

    ndpi_exit_detection_module(ndpi_str);
    sqlite3_close(db);

    return 0;
}

