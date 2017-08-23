#include <stdio.h>
#include <stdlib.h>
#include <string.h>
 
void PrintHex(char* buffer,int length)
{
	int i;
    for (i = 0; i < length; i++)
    {
        printf("%02X ", buffer[i] & 0xff);
    }
    printf("\n");
}

typedef struct virus virus;
struct virus 
{
    unsigned short length;
    char name[16];
    char signature[];
};

typedef struct link link;
struct link 
{
    virus *v;
    link *next;
};

void PrintVirus(virus *v)
{
    if(v != NULL)
    {
        printf("Virus name: %s\n", v->name);
        printf("Virus size: %i\n", v->length);
        printf("signature:\n");
        PrintHex(v->signature, v->length);
        printf("\n");
    }
}

void list_print(link* virus_list)
{
    if(virus_list != NULL)
    {
        PrintVirus(virus_list->v);
        list_print(virus_list->next);
    }
}

link* list_append(link* virus_list, virus* data)
{
    link* new = (link*)malloc(sizeof(link)+sizeof(data));
    new->v = data;
    new->next = NULL;
    if(virus_list != NULL)
    {
        link* it = virus_list;
        while(it->next != NULL)
            it = it->next;
        it->next = new;
        return virus_list;
    }
    else
        return new;
}
     
void list_free(link* virus_list)
{
    link* next;
    while (virus_list !=NULL)
    {
        next = virus_list->next;
        free(virus_list->v);
        free(virus_list);
        virus_list = next;
    }
}

int mycmp(const void *str1, const void *str2, size_t n)
{
    size_t i = 0;
    const char* p_str1 = str1;
    const char* p_str2 = str2;
    for(i = 0; i < n; i++)
    {
        if(*p_str1 != *p_str2)
            return *p_str1 - *p_str2;
        p_str1++;
        p_str2++;
    }
    return 0;
}

void detect_virus(char *buffer, link *virus_list, unsigned int size, int flag)
{
    int pos;
    link* vir = virus_list;
    virus* lastVirus = NULL;
    int lastPos = 0;
    unsigned short len;
    while (vir != NULL)
    {
        for(pos = 0; pos < size; pos++)
        {
            len = vir->v->length;
            if(mycmp(&buffer[pos], &(vir->v->signature), len) == 0)
            {
                if(flag == 0)
                {
                    printf("*****  Virus found!  *****\n");
                    printf("Starting byte of the suspected file: %i\n", pos);
                    printf("Virus name: %s\n", vir->v->name);
                    printf("Size of the virus signature: %i\n", len);
                }
                if(flag == 1)
                {                   
                    lastVirus = vir->v;
                    lastPos = pos;
                }
            }   
        }
        vir = vir->next;
    }
    if(flag == 1 && lastVirus != NULL)
    {
        printf("*****  Virus found!  *****\n");
        printf("Starting byte of the suspected file: %i\n", lastPos);
        printf("Virus name: %s\n", lastVirus->name);
        printf("Size of the virus signature: %i\n", lastVirus->length);
    }
}

int getFileEnd(FILE* file)
{
    int ans;
    fseek(file,0,SEEK_END);
    ans = ftell(file);
    rewind(file);
    return ans;
}

unsigned short little(char buffer[])
{
    return buffer[1]*16+buffer[0]*1;
}

unsigned short big(char buffer[])
{
    return buffer[0]*16+buffer[1]*1;
}

int main(int argc, char **argv)
{
    int printLast = 0;
    int j;
    int pos = 0;
    int fileend;
    link * head = NULL;
    char endian[1];
    char buffer[2];
    unsigned short length;
    unsigned short (*func)(char[]);
    FILE* file;
    FILE* sigFile = fopen("signatures","rb");
    if(argc<2)
        exit(1);              
    for(j = 1; j < argc; j++)
    {
        if(strcmp(argv[j], "-l") == 0)
        {
            printLast = 1;
        }
        else
        {
            file = fopen(argv[j],"rb");
        }
    } 
    if(sigFile)
    {
        fileend = getFileEnd(sigFile);
        fread(endian, 1, 1, sigFile);
        if(endian[0] == 0)
            func = &little;
        else
            func = &big;

        while(pos < fileend)
        {
            fread(buffer, 1, 2, sigFile);
            length = func(buffer);
            virus* vir = (virus*)malloc(length);
            vir->length = length-18;
            fread(vir->name, 1, 16, sigFile);
            fread(vir->signature, 1, vir->length, sigFile);
            pos = ftell(sigFile);
            head = list_append(head, vir);
        }
        fclose(sigFile);

        fileend = getFileEnd(file);
        char* filebuff = (char*)malloc(fileend);
        pos = fread(filebuff, 1, fileend, file);
        detect_virus(filebuff, head, pos, printLast);
        fclose(file);
        free(filebuff);
        list_free(head);
        return 0;
    }
    else
        return 1;
}