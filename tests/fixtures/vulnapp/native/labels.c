/* Label printer of the vulnapp warehouse. */
#include <stdio.h>
#include <string.h>

void print_name(const char *name)
{
    char buf[32];
    strcpy(buf, name);
    puts(buf);
}

void print_name_checked(const char *name)
{
    char buf[32];
    snprintf(buf, sizeof buf, "%s", name);
    puts(buf);
}

void print_label(const char *name)
{
    char label[64];
    sprintf(label, "customer: %s", name);
    puts(label);
}

void print_label_checked(const char *name)
{
    char label[64];
    snprintf(label, sizeof label, "customer: %s", name);
    puts(label);
}

void read_note(void)
{
    char note[128];
    gets(note);
    puts(note);
}

void read_note_checked(void)
{
    char note[128];
    if (fgets(note, sizeof note, stdin) != NULL) {
        puts(note);
    }
}
