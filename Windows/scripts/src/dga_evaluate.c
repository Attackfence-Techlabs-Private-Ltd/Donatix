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
    const char *update_query = "UPDATE dns_query_data SET isDGA = ? WHERE qname = ?;";
    /* isDGA IS NULL means not yet evaluated. Every name is marked afterwards,
       1 for a DGA hit and 0 for a clean name, so no name is examined twice. */
    char query[] = "SELECT DISTINCT qname FROM dns_query_data WHERE qname != '' AND isDGA IS NULL;";
    int num_detections = 0;
    rc = sqlite3_prepare_v2(db, query, -1, &stmt, 0);
    if (rc == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *hostname = (const char*)sqlite3_column_text(stmt, 0);
            int is_dga = ndpi_check_dga_name(ndpi_str, NULL, hostname, 1, 1) ? 1 : 0;
            sqlite3_stmt *stmt_update;

            if (verbose)
                printf(is_dga ? "DGA %s\n" : "NON DGA %s\n", hostname);

            rc = sqlite3_prepare_v2(db, update_query, -1, &stmt_update, 0);
            if (rc != SQLITE_OK) {
                fprintf(stderr, "Failed to prepare update statement: %s\n", sqlite3_errmsg(db));
                continue;  /* nothing to bind or step against */
            }
            if (sqlite3_bind_int(stmt_update, 1, is_dga) != SQLITE_OK ||
                sqlite3_bind_text(stmt_update, 2, hostname, -1, SQLITE_STATIC) != SQLITE_OK) {
                fprintf(stderr, "Failed to bind parameters: %s for hostname: %s\n",
                        sqlite3_errmsg(db), hostname);
                sqlite3_finalize(stmt_update);
                continue;
            }

            if (sqlite3_step(stmt_update) != SQLITE_DONE) {
                fprintf(stderr, "Update failed: %s for hostname: %s\n", sqlite3_errmsg(db), hostname);
            } else if (is_dga) {
                num_detections++;
            }
            sqlite3_finalize(stmt_update);
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
    /* Path may be given as argv[1]; the compiled-in default is the Windows install. */
    const char *db_path = (argc > 1) ? argv[1]
                                     : "C:\\Donatix\\Windows\\scripts\\src\\networkdata.db";
    int rc = sqlite3_open(db_path, &db);

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

