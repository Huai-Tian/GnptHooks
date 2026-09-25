//GnptHooks 重定位跳板单元测试(用户态Linux x64)——RIP-rel超距改写验证
//被测逻辑镜像自 GnptHooks/hook.c(HookRewriteRipRelImm64/HookBuildRelocTrampoline),
//**改动必须双向同步**。验证维度: 字节断言(改写/重算形态)+真实CPU执行级
//语义等价(黄金断言: lea r10,[rip+X] 与改写后 mov r10,imm64 结果一致)。
//
//用法(Linux/WSL x64):
//  gcc -O2 -o /tmp/test_reloc DbgTools/test_reloc.c GnptHooks/LDasm.c -D__fastcall=
//  /tmp/test_reloc
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>

//==================== WDK类型/运行时 shim ====================
typedef uint8_t  UCHAR;   typedef uint16_t USHORT;
typedef uint32_t ULONG;   typedef int32_t  LONG;
typedef uint64_t ULONG64; typedef int64_t  LONG64;
typedef unsigned char *PUCHAR; typedef void *PVOID;
typedef uint32_t *PULONG;
typedef uint32_t ULONG32;
typedef int BOOLEAN;
#define TRUE 1
#define FALSE 0
#define NT_SUCCESS(s) ((int)(s) >= 0)

//LDasm接口(与GnptHooks/LDasm.h逐字段一致)
#define F_INVALID 0x01
#define F_PREFIX  0x02
#define F_REX     0x04
#define F_MODRM   0x08
#define F_SIB     0x10
#define F_DISP    0x20
#define F_IMM     0x40
#define F_RELATIVE 0x80
typedef struct _ldasm_data
{
	UCHAR  flags;
	UCHAR  rex;
	UCHAR  modrm;
	UCHAR  sib;
	UCHAR  opcd_offset;
	UCHAR  opcd_size;
	UCHAR  disp_offset;
	UCHAR  disp_size;
	UCHAR  imm_offset;
	UCHAR  imm_size;
} ldasm_data;
unsigned int ldasm(void* code, ldasm_data* ld, ULONG is64);

//池shim: 生成物需执行级验证→RWX arena bump分配(近/远距由测试布局控制)
#define HOOK_REPLAY_BUF 96
static PUCHAR g_arena;      //arena基址(测试mmap控制与桩的相对距离)
static size_t g_arenaOff;
static PVOID ExAllocatePoolWithTag(int a, size_t sz, int tag)
{
	(void)a; (void)tag;
	if (g_arena == NULL || g_arenaOff + sz > 0x10000)
	{
		return NULL;
	}
	PUCHAR p = g_arena + g_arenaOff;
	g_arenaOff += sz;
	return p;
}
static void RtlZeroMemory(void* p, size_t n) { memset(p, 0, n); }
static void RtlCopyMemory(void* d, const void* s, size_t n) { memcpy(d, s, n); }
static void ExFreePoolWithTag(void* p, int t)
{
	(void)t;   //arena整体回收
}
#define FlLog printf

//==================== 镜像: GnptHooks/hook.c (同步区) ====================
//改写记录(回扫自检用): At=生成物内偏移 OldLen=源指令长度 Value=直存值
typedef struct _HOOK_REWRITE_REC
{
	ULONG   At;
	ULONG   OldLen;
	ULONG64 Value;
} HOOK_REWRITE_REC;
#define HOOK_MAX_REWRITES 8

//lea reg,[rip+disp32]→mov reg,imm64绝对直存(RIP-rel超±2GB改写)。
//仅收无前缀REX.W lea(modrm mod=00 rm=101, 7B形态); 直存值=原绝对
//有效地址, 语义等价(模块内相对偏移运行期不变, KASLR下恒真)。
//mov等内存加载源不在改写范围=拒(需保持逐字语义, 防越权扩面)
static ULONG HookRewriteRipRelImm64(PUCHAR Dst, ldasm_data* Ld,
	ULONG OldLen, ULONG64 Value)
{
	if (OldLen != 7 || Ld->opcd_offset != 1 || Ld->opcd_size != 1 ||
		Dst[1] != 0x8D || (Ld->flags & F_PREFIX) || (Ld->flags & F_SIB) ||
		Ld->imm_size != 0 || Ld->disp_size != 4 || (Ld->rex & 0x08) == 0)
	{
		return 0;    //非"REX.W 8D /r"纯净7B形态=拒
	}
	if ((Ld->modrm & 0xC7) != 0x05)    //mod=00 rm=101=[rip+disp32]
	{
		return 0;
	}
	ULONG reg = ((Ld->modrm >> 3) & 7) + ((Ld->rex & 0x04) ? 8 : 0);
	Dst[0] = (UCHAR)(0x48 | (reg >= 8 ? 1 : 0));    //REX.W(+B)
	Dst[1] = (UCHAR)(0xB8 | (reg & 7));             //mov reg,imm64
	*(ULONG64*)(Dst + 2) = Value;
	return 10;
}

//LDE重定位跳板生成器: 见GnptHooks/hook.c头注释①~⑤(此处镜像体, 勿改单侧)
static PUCHAR HookBuildRelocTrampoline(ULONG64 Target, ULONG MinLen, PULONG OutLen)
{
	if (OutLen != NULL)
	{
		*OutLen = 0;
	}
	PUCHAR buf = (PUCHAR)ExAllocatePoolWithTag(0, HOOK_REPLAY_BUF, 0);
	if (buf == NULL)
	{
		FlLog("[Reloc] 拒绝: 跳板缓冲分配失败\n");
		return NULL;
	}
	RtlZeroMemory(buf, HOOK_REPLAY_BUF);
	ULONG total = 0;
	ULONG64 src = Target;
	BOOLEAN bad = FALSE;
	HOOK_REWRITE_REC rewTab[HOOK_MAX_REWRITES];
	ULONG rewCount = 0;
	//循环按源侧覆盖长判定(非生成物长度): 改写膨胀不得计入"已
	//跳过patch区"的账——否则源侧<14即停, 跳回点落patch内=死循环
	while ((ULONG)(src - Target) < MinLen)
	{
		ldasm_data ld = { 0 };
		ULONG len = ldasm((PVOID)src, &ld, TRUE);
		if (len == 0 || (ld.flags & F_INVALID) || total + len > 80)
		{
			FlLog("[Reloc] 拒绝: 偏移+%u处指令解码失败/超长(len=%u flags=%02X)\n",
				total, len, (ULONG)ld.flags);
			bad = TRUE;
			break;
		}
		//相对分支=拒
		if ((ld.flags & F_IMM) && (ld.flags & F_RELATIVE))
		{
			FlLog("[Reloc] 拒绝: 偏移+%u处相对分支指令(%02X %02X...)——prologue不可重定位\n",
				total, *(PUCHAR)src, *((PUCHAR)src + 1));
			bad = TRUE;
			break;
		}
		RtlCopyMemory(buf + total, (PVOID)src, len);
		//RIP-relative数据寻址(非分支): 保绝对有效地址不变。
		//近区(±2GB内)=重算disp32; 超距(Zw桩形如lea r10,[rip±2TB])=
		//改写为等价mov reg,imm64绝对直存(见HookRewriteRipRelImm64)
		if ((ld.flags & F_DISP) && (ld.flags & F_RELATIVE) && ld.disp_size == 4)
		{
			LONG64 oldDisp = *(LONG*)(buf + total + ld.disp_offset);
			ULONG64 effective = src + len + (ULONG64)oldDisp;
			LONG64 newDisp = (LONG64)effective - (LONG64)(buf + total + len);
			if (newDisp >= -0x80000000LL && newDisp <= 0x7FFFFFFFLL)
			{
				*(LONG*)(buf + total + ld.disp_offset) = (LONG)newDisp;
			}
			else
			{
				//超±2GB: lea reg,[rip+d]→mov reg,imm64直存。
				//生成物按新长推进, 源/自检按原长推进(两账分开)
				ULONG rew = 0;
				if (rewCount < HOOK_MAX_REWRITES &&
					total + 10 + 14 <= HOOK_REPLAY_BUF)
				{
					rew = HookRewriteRipRelImm64(buf + total, &ld, len, effective);
				}
				if (rew == 0)
				{
					FlLog("[Reloc] 拒绝: 偏移+%u处RIP-rel超±2GB且不可改写"
						"(disp需%llX 字节%02X %02X %02X)\n",
						total, (long long)newDisp,
						*(PUCHAR)src, *((PUCHAR)src + 1), *((PUCHAR)src + 2));
					bad = TRUE;
					break;
				}
				rewTab[rewCount].At = total;
				rewTab[rewCount].OldLen = len;
				rewTab[rewCount].Value = effective;
				rewCount++;
				total += rew;    //生成物: mov reg,imm64=10B
				src += len;      //源: 原指令长度
				continue;
			}
		}
		total += len;
		src += len;
	}
	if (!bad)
	{
		//尾接位置无关绝对跳转 → Target+源覆盖长(=src; 改写后生成
		//物长度≠源覆盖长, 跳回点必须按源侧算, 否则落指令中途)
		buf[total] = 0xFF;
		buf[total + 1] = 0x25;
		*(ULONG32*)(buf + total + 2) = 0;
		*(ULONG64*)(buf + total + 6) = src;
		//回扫自检: 按CPU视角重新解码生成物, 与原始指令序列逐条比对
		ULONG chk = 0;
		ULONG64 ori = Target;
		while (chk < total && !bad)
		{
			ldasm_data ldNew = { 0 };
			ldasm_data ldOld = { 0 };
			ULONG lNew = ldasm(buf + chk, &ldNew, TRUE);
			ULONG lOld = ldasm((PVOID)ori, &ldOld, TRUE);
			//改写段: 不比字节(必然不同), 验解码有效+双长度吻合+
			//直存值==改写时记录的绝对有效地址(等价性黄金校验)
			ULONG r;
			for (r = 0; r < rewCount; r++)
			{
				if (rewTab[r].At == chk)
				{
					break;
				}
			}
			if (r < rewCount)
			{
				if (lNew == 0 || (ldNew.flags & F_INVALID) || lNew != 10 ||
					lOld != rewTab[r].OldLen ||
					(buf[chk] & 0xF0) != 0x40 || (buf[chk] & 0x08) == 0 ||
					(buf[chk + 1] & 0xF8) != 0xB8 ||
					*(ULONG64*)(buf + chk + 2) != rewTab[r].Value)
				{
					FlLog("[Reloc] 回扫自检FAIL: 改写段偏移+%u校验不符"
						"(新len=%u 旧len=%u 直存=%llX 应存=%llX)\n",
						chk, lNew, lOld,
						(long long)*(ULONG64*)(buf + chk + 2),
						(long long)rewTab[r].Value);
					bad = TRUE;
					break;
				}
				chk += lNew;
				ori += rewTab[r].OldLen;
				continue;
			}
			if (lNew == 0 || lNew != lOld || (ldNew.flags & F_INVALID))
			{
				FlLog("[Reloc] 回扫自检FAIL: 生成物偏移+%u解码异常(新len=%u 旧len=%u)\n",
					chk, lNew, lOld);
				bad = TRUE;
				break;
			}
			//逐字节比对(disp区=已重算, 跳过)
			ULONG dispStart = (ULONG)ldNew.disp_offset;
			ULONG dispEnd = dispStart + ldNew.disp_size;
			for (ULONG k = 0; k < lNew; k++)
			{
				if (k >= dispStart && k < dispEnd)
				{
					continue;
				}
				if (buf[chk + k] != *(PUCHAR)(ori + k))
				{
					FlLog("[Reloc] 回扫自检FAIL: 生成物偏移+%u字节%u不符(%02X vs %02X)\n",
						chk, k, buf[chk + k], *(PUCHAR)(ori + k));
					bad = TRUE;
					break;
				}
			}
			chk += lNew;
			ori += lOld;
		}
	}
	if (bad)
	{
		ExFreePoolWithTag(buf, 0);
		return NULL;
	}
	if (OutLen != NULL)
	{
		//源侧覆盖长(≠生成物长度): CodePage还原宽度+尾跳落点依据
		*OutLen = (ULONG)(src - Target);
	}
	return buf;
}
//==================== 镜像区结束 ====================

//==================== 测试设施 ====================
static int g_fail = 0;
#define CHECK(cond, ...) do { \
	if (!(cond)) { g_fail++; printf("  [FAIL] " __VA_ARGS__); } \
	else { printf("  [ OK ] " __VA_ARGS__); } } while (0)

//RWX区: 桩区(距arena 4GB→超距路径) + 近区(桩B与arena同区→重算路径)
#define REGION_FAR   0x100000000000ULL   //桩A/C/D
#define REGION_NEAR  0x100100000000ULL   //桩B + arena(距4GB远区→A超距)
static PUCHAR stubFar;    //=REGION_FAR基址
static PUCHAR stubNear;   //=REGION_NEAR基址

//桩写字节辅助
static PUCHAR Put(PUCHAR p, const void* b, size_t n)
{
	memcpy(p, b, n);
	return p + n;
}

//12字节通用前缀(模拟Zw桩prologue: mov r10,rcx + mov eax,0x6D + nop4)
static const UCHAR g_prefix12[12] =
{
	0x4C, 0x8B, 0xD1,             //mov r10,rcx
	0xB8, 0x6D, 0x00, 0x00, 0x00, //mov eax,0x6D
	0x0F, 0x1F, 0x40, 0x00        //nop dword[rax+0]
};

//跳板执行: 传rcx=arg1, 回收rax/rdx(桩在跳回点用mov rdx,r10暴露r10)
typedef struct { ULONG64 rax; ULONG64 rdx; } CALLRES;
static CALLRES CallTramp(void* tramp, ULONG64 arg1)
{
	CALLRES r;
	__asm__ volatile(
		"movq %2, %%rcx\n\t"
		"call *%3\n\t"
		: "=a"(r.rax), "=d"(r.rdx)
		: "r"(arg1), "r"(tramp)
		: "rbx", "rsi", "rdi", "r8", "r9", "r10", "r11", "memory", "cc");
	return r;
}

//==================== 用例 ====================
//A: 超距lea r10,[rip+X] → 改写mov r10,imm64, 执行级语义验证
static void CaseA(void)
{
	printf("[A] Zw桩形态: 超距lea r10,[rip+X](arena距桩4GB)\n");
	PUCHAR stub = stubFar;
	PUCHAR p = stub;
	p = Put(p, g_prefix12, 12);
	*(p++) = 0x4C; *(p++) = 0x8D; *(p++) = 0x15;    //lea r10,[rip+d]
	*(LONG*)p = 0xD9; p += 4;                        //eff=桩+19+0xD9
	ULONG64 eff = (ULONG64)stub + 19 + 0xD9;
	*(ULONG64*)((PUCHAR)stub + 0xD9) = 0xFEEDFACECAFEBEEFULL;  //目标数据
	//跳回点(桩+19): 暴露r10→rdx, 置rax=0x1234, ret
	PUCHAR q = (PUCHAR)stub + 19;
	q = Put(q, (UCHAR[]){0x4C, 0x89, 0xD2}, 3);           //mov rdx,r10
	q = Put(q, (UCHAR[]){0xB8, 0x34, 0x12, 0x00, 0x00}, 5); //mov eax,0x1234
	*q = 0xC3;
	ULONG len = 0;
	PUCHAR tr = HookBuildRelocTrampoline((ULONG64)stub, 14, &len);
	CHECK(tr != NULL, "跳板生成成功\n");
	if (tr == NULL) { return; }
	CHECK(len == 19, "OutLen=源覆盖长19 (实际%u)\n", len);
	CHECK(tr[12] == 0x49 && tr[13] == 0xBA,
		"偏移+12改写为 mov r10,imm64 (49 BA)\n");
	CHECK(*(ULONG64*)(tr + 14) == eff,
		"直存imm64==原绝对有效地址 (%llX)\n", (unsigned long long)eff);
	ULONG64 jmpBack = *(ULONG64*)(tr + 22 + 6);
	CHECK(jmpBack == (ULONG64)stub + 19,
		"尾跳落点=桩+19源侧 (实际%llX)\n", (unsigned long long)jmpBack);
	CALLRES r = CallTramp(tr, 0x1111);
	CHECK(r.rax == 0x1234, "执行: 跳回点正确返回 rax=0x1234 (实际%llX)\n",
		(unsigned long long)r.rax);
	CHECK(r.rdx == eff, "执行: r10语义等价 rdx==eff (实际%llX)\n",
		(unsigned long long)r.rdx);
}

//B: 近距RIP-rel(±2GB内) → 走disp32重算老路径, 执行级验证
static void CaseB(void)
{
	printf("[B] 回归: 近距RIP-rel(桩与arena同区4MB)走disp32重算\n");
	PUCHAR stub = stubNear;
	PUCHAR p = stub;
	p = Put(p, g_prefix12, 12);
	*(p++) = 0x4C; *(p++) = 0x8D; *(p++) = 0x15;    //lea r10,[rip+6]
	*(LONG*)p = 6; p += 4;                            //eff=桩+25
	ULONG64 eff = (ULONG64)stub + 25;
	*(ULONG64*)(stub + 25) = 0x1234567890ABCDEFULL;
	PUCHAR q = (PUCHAR)stub + 19;
	q = Put(q, (UCHAR[]){0x4C, 0x89, 0xD2}, 3);
	q = Put(q, (UCHAR[]){0xB8, 0x34, 0x12, 0x00, 0x00}, 5);
	*q = 0xC3;
	ULONG len = 0;
	PUCHAR tr = HookBuildRelocTrampoline((ULONG64)stub, 14, &len);
	CHECK(tr != NULL, "跳板生成成功\n");
	if (tr == NULL) { return; }
	CHECK(len == 19, "OutLen=19 (实际%u)\n", len);
	CHECK(tr[12] == 0x4C && tr[13] == 0x8D && tr[14] == 0x15,
		"近距保形: lea r10,[rip+d] 原样\n");
	LONG disp = *(LONG*)(tr + 15);
	CHECK((ULONG64)(tr + 19 + disp) == eff,
		"重算disp32保持绝对有效地址 (eff=%llX)\n", (unsigned long long)eff);
	CALLRES r = CallTramp(tr, 0x2222);
	CHECK(r.rax == 0x1234 && r.rdx == eff,
		"执行: rax=0x1234 rdx==eff (语义正确)\n");
}

//C: 超距mov r10,[rip+X](内存加载) → 改写器拒绝→整体拒绝
static void CaseC(void)
{
	printf("[C] 拒绝: 超距mov r10,[rip+X]非lea不可改写\n");
	PUCHAR stub = stubFar + 0x1000;
	PUCHAR p = stub;
	p = Put(p, g_prefix12, 12);
	*(p++) = 0x4C; *(p++) = 0x8B; *(p++) = 0x15;    //mov r10,[rip+6]
	*(LONG*)p = 6; p += 4;
	ULONG len = 0;
	PUCHAR tr = HookBuildRelocTrampoline((ULONG64)stub, 14, &len);
	CHECK(tr == NULL, "按预期拒绝(日志见上: 字节4C 8B 15)\n");
}

//D: 超距lea rdx,[rip+X](REX.R=0路径) → 改写mov rdx,imm64(48 BA)
static void CaseD(void)
{
	printf("[D] 寄存器映射: 超距lea rdx,[rip+X]→mov rdx,imm64(48 BA)\n");
	PUCHAR stub = stubFar + 0x2000;
	PUCHAR p = stub;
	p = Put(p, g_prefix12, 12);
	*(p++) = 0x49; *(p++) = 0x8D; *(p++) = 0x15;    //lea rdx,[rip+d]
	*(LONG*)p = 0x30; p += 4;                        //eff=桩+19+0x30
	ULONG64 eff = (ULONG64)stub + 19 + 0x30;
	ULONG len = 0;
	PUCHAR tr = HookBuildRelocTrampoline((ULONG64)stub, 14, &len);
	CHECK(tr != NULL, "跳板生成成功\n");
	if (tr == NULL) { return; }
	CHECK(tr[12] == 0x48 && tr[13] == 0xBA,
		"改写为 mov rdx,imm64 (48 BA)\n");
	CHECK(*(ULONG64*)(tr + 14) == eff, "直存imm64==有效地址 (%llX)\n",
		(unsigned long long)eff);
	CHECK(len == 19, "OutLen=19 (实际%u)\n", len);
}

int main(void)
{
	//布局: 远区(桩A/C/D)——arena(近区)距其4GB → RIP-rel超±2GB;
	//      近区(桩B)与arena同区(相距~4MB) → 走重算路径
	stubFar = (PUCHAR)mmap((PVOID)REGION_FAR, 0x10000,
		PROT_READ | PROT_WRITE | PROT_EXEC,
		MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	stubNear = (PUCHAR)mmap((PVOID)REGION_NEAR, 0x10000,
		PROT_READ | PROT_WRITE | PROT_EXEC,
		MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	if (stubFar == MAP_FAILED || stubNear == MAP_FAILED)
	{
		printf("mmap失败\n");
		return 2;
	}
	g_arena = stubNear + 0x1000;    //arena与桩B同区(近距)
	g_arenaOff = 0;
	CaseA();
	CaseB();
	CaseC();
	CaseD();
	printf(g_fail == 0 ? "全部通过\n" : "失败%u项\n", g_fail);
	return g_fail == 0 ? 0 : 1;
}
