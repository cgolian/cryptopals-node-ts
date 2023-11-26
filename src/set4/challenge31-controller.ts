import * as crypto from 'crypto';
import express from 'express';
import morgan from 'morgan';
import {computeHMACwSHA1, insecureCompare} from './challenge31';

const app = express();
app.use(morgan('common'));

const hmacKey = crypto.randomBytes(16);

app.get('/test', (req: express.Request, res: express.Response) => {
    const { file, signature } = req.query;
    const signatureBuffer = Buffer.from(signature as string, 'hex');
    const computedHmac = computeHMACwSHA1(Buffer.from(file as string), hmacKey);
    insecureCompare(computedHmac, signatureBuffer)
        .then((result: boolean) => res.status(result ? 200 : 500).end());
});

app.listen(3000, () => {
    console.log(`Started listening at port 3000`);
});