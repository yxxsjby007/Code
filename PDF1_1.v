module pdf_decrypt(
    input         clk,
    input         rst_n,
    input         start,
    input  [63:0] pwd_hash,   // 候选密码的哈希值(预处理后)
    input  [31:0] salt_0,     // Salt部分0-3
    input  [31:0] salt_1,
    input  [31:0] salt_2,
    input  [31:0] salt_3,
    input  [31:0] P,          // 权限标志
    input  [255:0] o_hash,    // 所有者哈希值
    input  [127:0] target,    // 目标哈希值
    output        valid      // 结果有效
    // output        match       // 密码匹配
);

// FSM状态定义
typedef enum logic [2:0] {
    IDLE,
    MD5_FIRST,
    MD5_SECOND,
    RC4_INIT,
    RC4_GEN,
    COMPARE,
    DONE
} state_t;

state_t current_state, next_state;

// MD5计算模块接口
wire        md5_start;
wire [511:0] md5_data;
wire [127:0] md5_digest;
wire        md5_done;

// RC4模块接口
wire        rc4_start;
wire [39:0] rc4_key;
wire [127:0] rc4_keystream;
wire        rc4_done;

// 数据寄存器
reg [511:0] data_blk;       // MD5处理块
reg [127:0] md5_first_out;  // 第一次MD5结果
reg [39:0] final_key;       // RC4的40位密钥
reg [127:0] encrypted;      // 加密结果

// 控制信号
reg load_md5_first, load_md5_second, load_rc4_key;

//========================= MD5计算模块 =========================//
md5_64PE_dsa(
    .clock      (clk)           ,
    .reset      (reset)         ,
    .start      (md5_start)     ,
    /////////////////////////////////
    // cfg field default for 64 PE //
    /////////////////////////////////
    .io_inputs  (md5_data)      ,
    .io_outputs (md5_digest)    ,
    .done       (md5_done)
)

// md5_ u_md5(
//     .clk        (clk),
//     .rst_n      (rst_n),
//     .start      (md5_start),
//     .data_block (md5_data),
//     .digest     (md5_digest),
//     .done       (md5_done)
// );

// 数据块生成逻辑 AOMUX
assign md5_data = 512{load_md5_first} & {pwd_hash, 64'h80, 352'h0, 32'h2000000, o_hash[255:128]} | 
                    512{load_md5_second} & {P, salt_0, salt_1, salt_2, salt_3,64'h80, 224'h0, 32'h30000000};

//========================= RC4模块 =============================//
rc4_40 u_rc4(
    .clk        (clk),
    .rst_n      (rst_n),
    .start      (rc4_start),
    .key        (rc4_key),
    .keystream  (rc4_keystream),
    .done       (rc4_done)
);

assign rc4_key = {md5_first_out[31:0], md5_digest[7:0]}; // 40位密钥

//========================= 控制逻辑 ============================//
always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        current_state <= IDLE;
    end else begin
        current_state <= next_state;
    end
end

always_comb begin
    next_state = current_state;
    case (current_state)
        IDLE: 
            if (start) next_state = MD5_FIRST;
        MD5_FIRST: 
            if (md5_done) next_state = MD5_SECOND;
        MD5_SECOND:
            if (md5_done) next_state = RC4_INIT;
        RC4_INIT:
            if (rc4_done) next_state = RC4_GEN;
        RC4_GEN:
            if (rc4_done) next_state = COMPARE;
        COMPARE:
            next_state = DONE;
        DONE:
            next_state = IDLE;
    endcase
end

// 控制信号生成
assign md5_start = (current_state == MD5_FIRST) || 
                  (current_state == MD5_SECOND);
assign load_md5_first = (current_state == MD5_FIRST);
assign load_md5_second = (current_state == MD5_SECOND);
assign rc4_start = (current_state == RC4_INIT);

// 数据锁存
always_ff @(posedge clk) begin
    if (current_state == MD5_FIRST && md5_done)
        md5_first_out <= md5_digest;
    if (current_state == RC4_GEN && rc4_done)
        encrypted <= rc4_keystream ^ 128'h2B7E151628AED2A6ABF7158; // 固定数据异或
end

// 结果比较
assign match = (encrypted == target);
assign valid = (current_state == DONE);

endmodule

// //========================= MD5流水线模块 ========================//
// module md5_pipeline #(
//     parameter STAGES = 16    // 每周期处理16步
// )(
//     input         clk,
//     input         rst_n,
//     input         start,
//     input  [511:0] data_block,
//     output [127:0] digest,
//     output        done
// );

// // 状态寄存器
// reg [127:0] state; // a,b,c,d
// reg [6:0] step;
// reg running;

// // 输入数据缓冲
// reg [511:0] data_blk;

// // 常数和消息扩展
// wire [31:0] K[0:63];
// wire [31:0] W[0:63];
// assign K = { ... }; // 初始化MD5常数
// assign W = {data_blk[31:0], data_blk[63:32], ...}; // 消息扩展

// always_ff @(posedge clk or negedge rst_n) begin
//     if (!rst_n) begin
//         running <= 0;
//         step <= 0;
//         state <= 128'h67452301_efcdab89_98badcfe_10325476;
//     end else begin
//         if (start) begin
//             data_blk <= data_block;
//             running <= 1;
//             step <= 0;
//         end else if (running) begin
//             // 每周期处理STAGES步
//             for (int i=0; i<STAGES; i++) begin
//                 // 更新MD5状态(state)
//                 // 此处实现MD5的压缩函数，涉及F,G,H,I函数和循环移位
//             end
//             step <= step + STAGES;
//             if (step >= 64) begin
//                 running <= 0;
//                 state <= state + initial_state; // 累加初始向量
//             end
//         end
//     end
// end

// assign digest = state;
// assign done = (step >= 64) && !running;

// endmodule

//========================= RC4-40模块 ==========================//
module rc4_40 (
    input         clk,
    input         rst_n,
    input         start,
    input  [39:0] key,
    output [127:0] keystream,
    output        done
);

reg [7:0] S[0:255];
reg [7:0] i, j;
reg [3:0] phase; // 0:IDLE, 1:KSA, 2:PRGA

// KSA阶段计数器
reg [8:0] ksa_cnt;

// PRGA输出计数
reg [3:0] prga_cnt;

always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        phase <= 0;
        ksa_cnt <= 0;
        prga_cnt <= 0;
    end else begin
        case (phase)
            0: if (start) begin
                // 初始化S盒
                for (int k=0; k<256; k++) S[k] <= k;
                phase <= 1;
                ksa_cnt <= 0;
                j <= 0;
            end
            1: begin // KSA
                if (ksa_cnt < 256) begin
                    j <= j + S[ksa_cnt] + key[ (ksa_cnt%5)*8 +:8 ];
                    // 交换S[i]和S[j]
                    S[ksa_cnt] <= S[j];
                    S[j] <= S[ksa_cnt];
                    ksa_cnt <= ksa_cnt + 1;
                end else begin
                    phase <= 2;
                    i <= 0;
                    j <= 0;
                    prga_cnt <= 0;
                end
            end
            2: begin // PRGA
                if (prga_cnt < 4) begin // 生成16字节
                    i <= i + 1;
                    j <= j + S[i];
                    // 交换S[i]和S[j]
                    {S[i], S[j]} <= {S[j], S[i]};
                    // 计算keystream字节
                    keystream[prga_cnt*32 +:8] <= S[ S[i] + S[j] ];
                    prga_cnt <= prga_cnt + 1;
                end else begin
                    phase <= 0;
                end
            end
        endcase
    end
end

assign done = (phase == 2) && (prga_cnt == 4);
assign keystream = ...; // 组合输出

endmodule