import axios, {AxiosRequestConfig, AxiosResponse} from "axios";

// register request interceptor used to measure time
axios.interceptors.request.use(function(config: AxiosRequestConfig) {
    Object.defineProperty(config, 'metadata', {
        value: { startTime: Date.now()},
        writable: true
    });
    return config;
}, function (error) {
    return Promise.reject(error);
});

// register response interceptor
axios.interceptors.response.use(function (response: AxiosResponse) {
    const enrichedConfig = response.config as { metadata: { startTime: number; endTime: number; duration: number}};
    // this should be handling the 200s returned
    enrichedConfig.metadata.endTime = Date.now();
    Object.defineProperty(response, 'duration', {
        value: enrichedConfig.metadata.endTime - enrichedConfig.metadata.startTime,
        writable: true
    });
    return response;
}, function (error) {
    // and this the 500s
    error.config.metadata.endTime = Date.now();
    error.duration = error.config.metadata.endTime - error.config.metadata.startTime;
    return Promise.reject(error);
});

export type HMACValidResponse = { success: boolean; responseTime: number};

export async function isHMACValid(file: string, signature: string): Promise<HMACValidResponse> {
    const requestUrl = `http://localhost:3000/test?file=${file}&signature=${signature}`;
    try {
        const response: { [key: string]: number } = await axios.get(requestUrl);
        return { success: true, responseTime: response.duration };
    } catch (error) {
        return { success: false, responseTime: (error as { duration: number }).duration };
    }
}

async function decryptHMACByteForPosition(file: string, signature: Buffer, position: number): Promise<number> {
    let response: HMACValidResponse;
    let failedIdx: number;
    for (let i = 0; i < 256; i++) {
        signature[position] = i;
        response = await isHMACValid(file, signature.toString('hex'));
        if (response.success) return i;
        failedIdx = Math.floor(response.responseTime / 50);
        if (failedIdx > position) return i;
    }
    throw Error(`Could not find valid HMAC byte`);
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars
async function findValidHMACForFile(file: string): Promise<string> {
    const signature = Buffer.alloc(20, 0x00);
    // for every character in HMAC digest
    for (let i = 0; i < signature.length; i++) {
        signature[i] = await decryptHMACByteForPosition(file, signature, i);
    }
    return Promise.resolve(signature.toString('hex'));
}