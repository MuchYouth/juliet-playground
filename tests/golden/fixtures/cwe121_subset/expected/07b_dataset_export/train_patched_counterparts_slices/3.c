    memset(VAR_1, 'A', 100-1); /* fill with 'A's */
        SNPRINTF(VAR_2, strlen(VAR_1), "%s", VAR_1);
#define SNPRINTF snprintf
