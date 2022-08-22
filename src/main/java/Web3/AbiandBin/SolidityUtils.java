package Web3.AbiandBin;

import org.web3j.codegen.SolidityFunctionWrapperGenerator;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.stream.Stream;

public class SolidityUtils {
    /**
     * 利用abi信息 与 bin信息 生成对应的abi,bin文件
     * @param abi 合约编译后的abi信息
     * @param bin 合约编译后的bin信息
     */
    public static void generateABIAndBIN(String abi,String bin,String abiFileName,String binFileName){

        File abiFile = new File("src/main/resources/"+abiFileName);
        File binFile = new File("src/main/resources/"+binFileName);
        BufferedOutputStream abiBos = null;
        BufferedOutputStream binBos = null;
        try{
            FileOutputStream abiFos = new FileOutputStream(abiFile);
            FileOutputStream binFos = new FileOutputStream(binFile);
            abiBos = new BufferedOutputStream(abiFos);
            binBos = new BufferedOutputStream(binFos);
            abiBos.write(abi.getBytes());
            abiBos.flush();
            binBos.write(bin.getBytes());
            binBos.flush();
        }catch (Exception e){
            e.printStackTrace();
        }finally {
            if(abiBos != null){
                try{
                    abiBos.close();;
                }catch (IOException e){
                    e.printStackTrace();
                }
            }
            if(binBos != null){
                try {
                    binBos.close();
                }catch (IOException e){
                    e.printStackTrace();
                }
            }
        }
    }
   public static void genAbi(){
        String abi = "[\n" +
                "\t{\n" +
                "\t\t\"inputs\": [],\n" +
                "\t\t\"name\": \"retrieve\",\n" +
                "\t\t\"outputs\": [\n" +
                "\t\t\t{\n" +
                "\t\t\t\t\"internalType\": \"uint256\",\n" +
                "\t\t\t\t\"name\": \"\",\n" +
                "\t\t\t\t\"type\": \"uint256\"\n" +
                "\t\t\t}\n" +
                "\t\t],\n" +
                "\t\t\"stateMutability\": \"view\",\n" +
                "\t\t\"type\": \"function\"\n" +
                "\t},\n" +
                "\t{\n" +
                "\t\t\"inputs\": [\n" +
                "\t\t\t{\n" +
                "\t\t\t\t\"internalType\": \"uint256\",\n" +
                "\t\t\t\t\"name\": \"num\",\n" +
                "\t\t\t\t\"type\": \"uint256\"\n" +
                "\t\t\t}\n" +
                "\t\t],\n" +
                "\t\t\"name\": \"store\",\n" +
                "\t\t\"outputs\": [],\n" +
                "\t\t\"stateMutability\": \"nonpayable\",\n" +
                "\t\t\"type\": \"function\"\n" +
                "\t}\n" +
                "]";
        String bin = "{\n" +
                "\t\"functionDebugData\": {},\n" +
                "\t\"generatedSources\": [],\n" +
                "\t\"linkReferences\": {},\n" +
                "\t\"object\": \"608060405234801561001057600080fd5b50610150806100206000396000f3fe608060405234801561001057600080fd5b50600436106100365760003560e01c80632e64cec11461003b5780636057361d14610059575b600080fd5b610043610075565b60405161005091906100a1565b60405180910390f35b610073600480360381019061006e91906100ed565b61007e565b005b60008054905090565b8060008190555050565b6000819050919050565b61009b81610088565b82525050565b60006020820190506100b66000830184610092565b92915050565b600080fd5b6100ca81610088565b81146100d557600080fd5b50565b6000813590506100e7816100c1565b92915050565b600060208284031215610103576101026100bc565b5b6000610111848285016100d8565b9150509291505056fea264697066735822122005d160d7f76cf393033d59a64019e4eac4fd1bfc66036fb96874f3343f112b5364736f6c634300080f0033\",\n" +
                "\t\"opcodes\": \"PUSH1 0x80 PUSH1 0x40 MSTORE CALLVALUE DUP1 ISZERO PUSH2 0x10 JUMPI PUSH1 0x0 DUP1 REVERT JUMPDEST POP PUSH2 0x150 DUP1 PUSH2 0x20 PUSH1 0x0 CODECOPY PUSH1 0x0 RETURN INVALID PUSH1 0x80 PUSH1 0x40 MSTORE CALLVALUE DUP1 ISZERO PUSH2 0x10 JUMPI PUSH1 0x0 DUP1 REVERT JUMPDEST POP PUSH1 0x4 CALLDATASIZE LT PUSH2 0x36 JUMPI PUSH1 0x0 CALLDATALOAD PUSH1 0xE0 SHR DUP1 PUSH4 0x2E64CEC1 EQ PUSH2 0x3B JUMPI DUP1 PUSH4 0x6057361D EQ PUSH2 0x59 JUMPI JUMPDEST PUSH1 0x0 DUP1 REVERT JUMPDEST PUSH2 0x43 PUSH2 0x75 JUMP JUMPDEST PUSH1 0x40 MLOAD PUSH2 0x50 SWAP2 SWAP1 PUSH2 0xA1 JUMP JUMPDEST PUSH1 0x40 MLOAD DUP1 SWAP2 SUB SWAP1 RETURN JUMPDEST PUSH2 0x73 PUSH1 0x4 DUP1 CALLDATASIZE SUB DUP2 ADD SWAP1 PUSH2 0x6E SWAP2 SWAP1 PUSH2 0xED JUMP JUMPDEST PUSH2 0x7E JUMP JUMPDEST STOP JUMPDEST PUSH1 0x0 DUP1 SLOAD SWAP1 POP SWAP1 JUMP JUMPDEST DUP1 PUSH1 0x0 DUP2 SWAP1 SSTORE POP POP JUMP JUMPDEST PUSH1 0x0 DUP2 SWAP1 POP SWAP2 SWAP1 POP JUMP JUMPDEST PUSH2 0x9B DUP2 PUSH2 0x88 JUMP JUMPDEST DUP3 MSTORE POP POP JUMP JUMPDEST PUSH1 0x0 PUSH1 0x20 DUP3 ADD SWAP1 POP PUSH2 0xB6 PUSH1 0x0 DUP4 ADD DUP5 PUSH2 0x92 JUMP JUMPDEST SWAP3 SWAP2 POP POP JUMP JUMPDEST PUSH1 0x0 DUP1 REVERT JUMPDEST PUSH2 0xCA DUP2 PUSH2 0x88 JUMP JUMPDEST DUP2 EQ PUSH2 0xD5 JUMPI PUSH1 0x0 DUP1 REVERT JUMPDEST POP JUMP JUMPDEST PUSH1 0x0 DUP2 CALLDATALOAD SWAP1 POP PUSH2 0xE7 DUP2 PUSH2 0xC1 JUMP JUMPDEST SWAP3 SWAP2 POP POP JUMP JUMPDEST PUSH1 0x0 PUSH1 0x20 DUP3 DUP5 SUB SLT ISZERO PUSH2 0x103 JUMPI PUSH2 0x102 PUSH2 0xBC JUMP JUMPDEST JUMPDEST PUSH1 0x0 PUSH2 0x111 DUP5 DUP3 DUP6 ADD PUSH2 0xD8 JUMP JUMPDEST SWAP2 POP POP SWAP3 SWAP2 POP POP JUMP INVALID LOG2 PUSH5 0x6970667358 0x22 SLT KECCAK256 SDIV 0xD1 PUSH1 0xD7 0xF7 PUSH13 0xF393033D59A64019E4EAC4FD1B 0xFC PUSH7 0x36FB96874F334 EXTCODEHASH GT 0x2B MSTORE8 PUSH5 0x736F6C6343 STOP ADDMOD 0xF STOP CALLER \",\n" +
                "\t\"sourceMap\": \"199:356:0:-:0;;;;;;;;;;;;;;;;;;;\"\n" +
                "}";

        String abiFileName = "Storage.abi";
        String binFileName = "Storage.bin";

        generateABIAndBIN(abi,bin,abiFileName,binFileName);
    }
    /**
     *
     * 生成合约的java代码
     * 其中 -p 为生成java代码的包路径此参数和 -o 参数配合使用，以便将java文件放入正确的路径当中
     * @param abiFile abi的文件路径
     * @param binFile bin的文件路径
     * @param generateFile 生成的java文件路径
     */
    public static void generateClass(String abiFile,String binFile,String generateFile){
        String[] args = Arrays.asList(
                "-a",abiFile,
                "-b",binFile,
                "-p","",
                "-o",generateFile
        ).toArray(new String[0]);
        Stream.of(args).forEach(System.out::println);
        SolidityFunctionWrapperGenerator.main(args);
    }
    public static void generateJavaFile(){
        String abiFile = "src/main/resources/DecPark.abi";
        String binFile = "src/main/resources/DecPark.bin";
        String generateFile = "src/main/java/TestDecPark";
        SolidityUtils.generateClass(abiFile,binFile,generateFile);
    }



}
