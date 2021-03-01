//
//  main.c
//  pract
//
//  Created by SUVANSH  ARORA on 16/02/21.
//

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int main(int argc, const char * argv[]) {
    // insert code here..
    char ch[16];
    printf("enter a string : ");
    scanf("%[^\n]s",ch);
    printf("%s",ch);
    int len=0;
    int i=0;
    while(ch[i]!='\0'){
        len++;
        i++;
    }
    int a,b;
    i=0;
    for( i=0;i<len;i+=2){
        printf("\n");
        printf("%c %c",ch[i],ch[i+1]);
        a=(int)ch[i];
        if(i+1!=len){
             b=(int)ch[i+1];}
        else
            b=0;
        int first[8]={0};
        int second[8]={0};
        int z=0;
        while(a>0){
            if(a%2==0)
            first[7-z]=0;
            else
                first[7-z]=1;
            a=a/2;
            z++;
        }
        z=0;
        while(b>0){
            if(b%2==0)
            second[7-z]=0;
            else
                second[7-z]=1;
            b=b/2;
            z++;
        }
        int msg[16];
        for(int j=0;j<8;j++)
        msg[j]=first[j];
        for(int j=8;j<16;j++)
        msg[j]=second[j-8];
        printf("\n");
        for(int j=0;j<16;j++)
        printf("%d",msg[j]);
        
    }
    for(int i=0;i<len;i++)
    printf("%c",ch[i]);
    return 0;
}
