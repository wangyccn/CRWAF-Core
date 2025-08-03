fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 编译proto文件
    tonic_build::compile_protos("proto/waf.proto")?;
    Ok(())
}