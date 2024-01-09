; ModuleID = 'bad.c'
source_filename = "bad.c"
target datalayout = "e-m:w-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-w64-windows-gnu"

%struct._charVoid = type { [16 x i8], ptr, ptr }

@.str = private unnamed_addr constant [32 x i8] c"0123456789abcdef0123456789abcde\00", align 1

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memcpy_18_bad() #0 {
  %1 = alloca ptr, align 8
  br label %2

2:                                                ; preds = %0
  %3 = call ptr @malloc(i64 noundef 32) #5
  store ptr %3, ptr %1, align 8
  %4 = load ptr, ptr %1, align 8
  %5 = icmp eq ptr %4, null
  br i1 %5, label %6, label %7

6:                                                ; preds = %2
  call void @exit(i32 noundef -1) #6
  unreachable

7:                                                ; preds = %2
  %8 = load ptr, ptr %1, align 8
  %9 = getelementptr inbounds %struct._charVoid, ptr %8, i32 0, i32 1
  store ptr @.str, ptr %9, align 8
  %10 = load ptr, ptr %1, align 8
  %11 = getelementptr inbounds %struct._charVoid, ptr %10, i32 0, i32 1
  %12 = load ptr, ptr %11, align 8
  call void @printLine(ptr noundef %12)
  %13 = load ptr, ptr %1, align 8
  %14 = getelementptr inbounds %struct._charVoid, ptr %13, i32 0, i32 0
  %15 = getelementptr inbounds [16 x i8], ptr %14, i64 0, i64 0
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %15, ptr align 1 @.str, i64 32, i1 false)
  %16 = load ptr, ptr %1, align 8
  %17 = getelementptr inbounds %struct._charVoid, ptr %16, i32 0, i32 0
  %18 = getelementptr inbounds [16 x i8], ptr %17, i64 0, i64 15
  store i8 0, ptr %18, align 1
  %19 = load ptr, ptr %1, align 8
  %20 = getelementptr inbounds %struct._charVoid, ptr %19, i32 0, i32 0
  %21 = getelementptr inbounds [16 x i8], ptr %20, i64 0, i64 0
  call void @printLine(ptr noundef %21)
  %22 = load ptr, ptr %1, align 8
  %23 = getelementptr inbounds %struct._charVoid, ptr %22, i32 0, i32 1
  %24 = load ptr, ptr %23, align 8
  call void @printLine(ptr noundef %24)
  %25 = load ptr, ptr %1, align 8
  call void @free(ptr noundef %25)
  ret void
}

; Function Attrs: allocsize(0)
declare dso_local ptr @malloc(i64 noundef) #1

; Function Attrs: noreturn nounwind
declare dso_local void @exit(i32 noundef) #2

declare dso_local void @printLine(ptr noundef) #3

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly, ptr noalias nocapture readonly, i64, i1 immarg) #4

declare dso_local void @free(ptr noundef) #3

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @main(i32 noundef %0, ptr noundef %1) #0 {
  %3 = alloca i32, align 4
  %4 = alloca i32, align 4
  %5 = alloca ptr, align 8
  store i32 0, ptr %3, align 4
  store i32 %0, ptr %4, align 4
  store ptr %1, ptr %5, align 8
  %6 = call i64 @time(ptr noundef null)
  %7 = trunc i64 %6 to i32
  call void @srand(i32 noundef %7)
  call void @CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memcpy_18_bad()
  ret i32 0
}

declare dso_local void @srand(i32 noundef) #3

declare dso_local i64 @time(ptr noundef) #3

attributes #0 = { noinline nounwind optnone uwtable "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { allocsize(0) "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #2 = { noreturn nounwind "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #3 = { "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #4 = { nocallback nofree nounwind willreturn memory(argmem: readwrite) }
attributes #5 = { allocsize(0) }
attributes #6 = { noreturn nounwind }

!llvm.module.flags = !{!0, !1, !2, !3}
!llvm.ident = !{!4}

!0 = !{i32 1, !"wchar_size", i32 2}
!1 = !{i32 8, !"PIC Level", i32 2}
!2 = !{i32 7, !"uwtable", i32 2}
!3 = !{i32 1, !"MaxTLSAlign", i32 65536}
!4 = !{!"clang version 17.0.1"}
