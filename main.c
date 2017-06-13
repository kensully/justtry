#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>


struct {
    char*name; char*occ;
} values[]={
    "Li Lei", "CEO",    "Han Meimei", "CPO",
    "Lily", "COO",         "Lucy", "CFO",

};
#define LEN(x) sizeof(x)/sizeof(x[0])

#define CREATE_TABLE_TASK_SQL     "create table task (binId INTEGER, cmdId VARCHAR(256), username VARCHAR(256), cmdSet VARCHAR(256), topic VARCHAR(256), tag VARCHAR(256), cronExpr VARCHAR(256), cronType VARCHAR(256), timeout INTEGER);"

#define INSERT_TABLE_TASK_SQL   "insert into task values (?, ?, ?, ?, ?, ?, ?, ?, ?);"

#define SELECT_ALL_TASK_SQL     "select * from task;"

#define UPDATE_TASK_SQL     "UPDATE TASK SET binId = ?, cmdId = ?, username = ?, cmdset = ?, cronExpr = ?, cronType = ?, timeout = ? WHERE topic = ? AND tag = ?;"

#define DELETE_ONE_TASK_SQL   "DELETE FROM task WHERE topic = ? AND tag = ?;"

typedef struct ops_context_s {
    sqlite3 *db;
} ops_context_t;

ops_context_t ctx;

typedef struct cron_task_s {
    long bin_id;
    char cmd_id[256];
    char username[256];
    char cmd_set[256];
    char topic[256];
    char tag[256];
    char cron_expr[256];
    char cron_type[128];
    long timeout;
} cron_task_t ;

int ops_db_init()
{
    sqlite3_open("./test.db", &ctx.db);
}

int ops_db_create_cron_table()
{
    sqlite3 *db = ctx.db;
    sqlite3_stmt *stmt;

    const char *err = NULL;
    if (sqlite3_prepare(db, CREATE_TABLE_TASK_SQL, strlen(CREATE_TABLE_TASK_SQL), &stmt, &err) != SQLITE_OK) {
        printf("prepared faild\n");
        printf("%s", err);
        return -1;
    }
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return 0;
}

int ops_db_insert_cron_task(cron_task_t *task)
{
    sqlite3 *db = ctx.db;
    sqlite3_stmt *stmt;

    const char *err = NULL;
    if (sqlite3_prepare(db, INSERT_TABLE_TASK_SQL, strlen(INSERT_TABLE_TASK_SQL), &stmt, &err) != SQLITE_OK) {
        printf("prepared faild\n");
        printf("%s", err);
        return -1;
    }

    sqlite3_bind_int(stmt,  1, task->bin_id);
    sqlite3_bind_text(stmt, 2, task->cmd_id,    strlen(task->cmd_id),   SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, task->username,  strlen(task->username), SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, task->cmd_set,   strlen(task->cmd_set),  SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, task->topic,     strlen(task->topic),    SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, task->tag,       strlen(task->tag),      SQLITE_STATIC);
    sqlite3_bind_text(stmt, 7, task->cron_expr, strlen(task->cron_expr), SQLITE_STATIC);
    sqlite3_bind_text(stmt, 8, task->cron_type, strlen(task->cron_type), SQLITE_STATIC);
    sqlite3_bind_int(stmt,  9, task->timeout);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return 0;
}

int ops_db_update_cron_task(cron_task_t *task)
{
    sqlite3 *db = ctx.db;
    sqlite3_stmt *stmt;

    const char *err = NULL;
    if (sqlite3_prepare(db, UPDATE_TASK_SQL, strlen(UPDATE_TASK_SQL), &stmt, &err) != SQLITE_OK) {
        printf("prepared faild\n");
        printf("%s", err);
        return -1;
    }



    sqlite3_bind_int(stmt,  1, task->bin_id);
    sqlite3_bind_text(stmt, 2, task->cmd_id,    strlen(task->cmd_id),   SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, task->username,  strlen(task->username), SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, task->cmd_set,   strlen(task->cmd_set),  SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, task->cron_expr, strlen(task->cron_expr), SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, task->cron_type, strlen(task->cron_type), SQLITE_STATIC);
    sqlite3_bind_int(stmt,  7, task->timeout);
    sqlite3_bind_text(stmt, 8, task->topic,     strlen(task->topic),    SQLITE_STATIC);
    sqlite3_bind_text(stmt, 9, task->tag,       strlen(task->tag),      SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return 0;
}

int ops_db_select_all_cron_task()
{
    sqlite3 *db = ctx.db;
    sqlite3_stmt *stmt;

    const char *err = NULL;
    if (sqlite3_prepare(db, SELECT_ALL_TASK_SQL, strlen(SELECT_ALL_TASK_SQL), &stmt, &err) != SQLITE_OK) {
        printf("prepared faild\n");
        printf("%s", err);
        return -1;
    }

    int i=0;
    while(SQLITE_DONE !=sqlite3_step(stmt))
    {
        printf("Result[%d]: bin_id=%d, cmd_id=%s, username=%s, cmd_set=%s, topic=%s, tag=%s, cron_expr=%s, cron_type=%s, timeout=%d\n",
               i++,
               sqlite3_column_int(stmt, 0),
               sqlite3_column_text(stmt, 1),
               sqlite3_column_text(stmt, 2),
               sqlite3_column_text(stmt, 3),
               sqlite3_column_text(stmt, 4),
               sqlite3_column_text(stmt, 5),
               sqlite3_column_text(stmt, 6),
               sqlite3_column_text(stmt, 7),
               sqlite3_column_int(stmt, 8)
               );
    }

    sqlite3_finalize(stmt);
}

int ops_db_delete_one_cron_task(char *topic, char *tag)
{
    sqlite3 *db = ctx.db;
    sqlite3_stmt *stmt;

    const char *err = NULL;
    if (sqlite3_prepare(db, DELETE_ONE_TASK_SQL, strlen(DELETE_ONE_TASK_SQL), &stmt, &err) != SQLITE_OK) {
        printf("prepared faild\n");
        printf("%s", err);
        return -1;
    }
    sqlite3_bind_text(stmt, 1, topic,  strlen(topic),   SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, tag,  strlen(tag),   SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

/*
void my_first_sqlite3_func()
{
    int i;
    sqlite3 *db;
    sqlite3_stmt *stmt;
    char name[16], occ[16];
    char*sql_drop="drop table if exists people;";
    char*sql_create="create table people (name, occupation);";
    char*sql_insert="insert into people values (?, ?);";
    char*sql_select="select * from people;";

    sqlite3_open("./test.db", &db);
    if( sqlite3_prepare(db, sql_drop, strlen(sql_drop), &stmt, NULL) != SQLITE_OK) {
        printf("prepared failed\n");
    }
    sqlite3_step(stmt);

    if(sqlite3_prepare(db, sql_create, strlen(sql_create), &stmt, NULL) != SQLITE_OK) {
        printf("prepared failed\n");
    }
    sqlite3_step(stmt);

    if( sqlite3_prepare(db, sql_insert, strlen(sql_insert), &stmt, NULL) != SQLITE_OK) {
        printf("prepared failed\n");
    }

    for(i=0;i<LEN(values);i++)
    {
        //printf("INSERT name=%s, occ=%s\n",values[i].name, values[i].occ);
        sqlite3_bind_text(stmt, 1, values[i].name, strlen(values[i].name), SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, values[i].occ, strlen(values[i].occ), SQLITE_STATIC);
        sqlite3_step(stmt);
        sqlite3_reset(stmt);
    }

    sqlite3_prepare(db, sql_select, strlen(sql_select), &stmt, NULL);
    i=0;
    while(SQLITE_DONE !=sqlite3_step(stmt))
    {
        printf("Result[%d]: name=%s, occ=%s\n",
               i++,
               sqlite3_column_text(stmt, 0),
               sqlite3_column_text(stmt, 1));
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
}
*/

int main(int argc, char* argv[])
{
    ops_db_init();
//    ops_db_create_cron_table();

    cron_task_t *task = (cron_task_t *)malloc(sizeof(cron_task_t));

    task->bin_id = 2;
    strcpy(task->cmd_id, "3de879a7fc");
    strcpy(task->cmd_set, "ls");
    strcpy(task->topic, "hellos1");
    strcpy(task->tag, "3d4");
    strcpy(task->cron_expr, "*/1, 2, 3 ,4, 5");
    strcpy(task->username, "root");
    strcpy(task->cron_type, "monitor");
    task->timeout = 4000;

//    ops_db_insert_cron_task(task);

    ops_db_select_all_cron_task();

//    ops_db_delete_one_cron_task("hellos", "3d4");
    printf("=============================================\n");

    task->bin_id=6;
    task->timeout = 5009;

    ops_db_update_cron_task(task);

    ops_db_select_all_cron_task();

//    ops_db_select_one_cron_task();
//    my_first_sqlite3_func();

    return 0;
}
