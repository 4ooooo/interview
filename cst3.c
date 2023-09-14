#include<stdio.h>
#include<stdlib.h>
typedef struct LNode {
        int data;
        char flag;
        struct LNode *next;
}LNode, *LinkList;
int main()
{
        int m,n,i;
        LNode *s;
        LinkList L;
        size_t list_size = 0;
        size_t node_size = sizeof(LNode);
        scanf("%d",&n);
        L=(LinkList)malloc(sizeof(LNode));
        L->next=NULL;
        for(i=0;i<n;i++)
        {
                s=(LNode*)malloc(sizeof(LNode));
                s->data=n-i;
                s->next=L->next;
                L->next=s;
        }//定义链表;
        //printf("%d",L->next->data);
        while(1)
        {
                scanf("%d",&m);
                if(m<n)
                {
                	s=L->next;
                	for(i=1;i<m;i++)
                	{
                		s=s->next;
					}
					if(s->flag<127)
					{
						s->flag++;
					}
					
				}
				else
					{
						s=L->next;
						while(s)
						{
							list_size += sizeof(LNode);
							printf("%d\n",s->flag);
							s=s->next;
						}
						printf("单个LNode节点的大小：%zu 字节\n", node_size);
						printf("整个链表占用的内存空间：%zu 字节\n", list_size);
						return 0;
					}
				
        }
        return 0;
}
