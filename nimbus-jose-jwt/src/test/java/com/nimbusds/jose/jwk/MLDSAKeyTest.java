/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.nimbusds.jose.jwk;


import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.crypto.utils.MLDSAUtils;
import com.nimbusds.jose.jwk.gen.MLDSAKeyGenerator;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.*;
import com.nimbusds.jwt.util.DateUtils;
import junit.framework.TestCase;
import org.jose4j.json.internal.json_simple.JSONObject;

import java.net.URI;
import java.security.*;
import java.util.*;

import static org.junit.Assert.assertNotEquals;


public class MLDSAKeyTest extends TestCase {


    private static final class ExampleKeyMLDSA44 {


        public static final JWSAlgorithm ALG = JWSAlgorithm.ML_DSA_44;


        public static final Base64URL pub = new Base64URL("unH59k4RuutY-pxvu24U5h8YZD2rSVtHU5qRZsoBmBMcRPgmu9VuNOVdteXi1zNIXjnqJg_GAAxepLqA00Vc3lO0bzRIKu39VFD8Lhuk8l0V-cFEJC-zm7UihxiQMMUEmOFxe3x1ixkKZ0jqmqP3rKryx8tSbtcXyfea64QhT6XNje2SoMP6FViBDxLHBQo2dwjRls0k5a-XSQSu2OTOiHLoaWsLe8pQ5FLNfTDqmkrawDEdZyxr3oSWJAsHQxRjcIiVzZuvwxYy1zl2STiP2vy_fTBaPemkleynQzqPg7oPCyXEE8bjnJbrfWkbNNN8438e6tHPIX4l7zTuzz98YPhLjt_d6EBdT4MldsYe-Y4KLyjaGHcAlTkk9oa5RhRwW89T0z_t1DSO3dvfKLUGXh8gd1BD6Fz5MfgpF5NjoafnQEqDjsAAhrCXY4b-Y3yYJEdX4_dp3dRGdHG_rWcPmgX4JG7lCnser4f8QGnDriqiAzJYEXeS8LzUngg_0bx0lqv_KcyU5IaLISFO0xZSU5mmEPvdSoDnyAcV8pV44qhLtAvd29n0ehG259oRihtljTWeiu9V60a1N2tbZVl5mEqSK-6_xZvNYA1TCdzNctvweH24unV7U3wer9XA9Q6kvJWDVJ4oKaQsKMrCSMlteBJMRxWbGK7ddUq6F7GdQw-3j2M-qdJvVKm9UPjY9rc1lPgol25-oJxTu7nxGlbJUH-4m5pevAN6NyZ6lfhbjWTKlxkrEKZvQXs_Yf6cpXEwpI_ZJeriq1UC1XHIpRkDwdOY9MH3an4RdDl2r9vGl_IwlKPNdh_5aF3jLgn7PCit1FNJAwC8fIncAXgAlgcXIpRXdfJk4bBiO89GGccSyDh2EgXYdpG3XvNgGWy7npuSoNTE7WIyblAk13UQuO4sdCbMIuriCdyfE73mvwj15xgb07RZRQtFGlFTmnFcIdZ90zDrWXDbANntv7KCKwNvoTuv64bY3HiGbj-NQ-U9eMylWVpvr4hrXcES8c9K3PqHWADZC0iIOvlzFv4VBoc_wVflcOrL_SIoaNFCNBAZZq-2v5lAgpJTqVOtqJ_HVraoSfcKy5g45p-qULunXj6Jwq21fobQiKubBKKOZwcJFyJD7F4ACKXOrz-HIvSHMCWW_9dVrRuCpJw0s0aVFbRqopDNhu446nqb4_EDYQM1tTHMozPd_jKxRRD0sH75X8ZoToxFSpLBDbtdWcenxj-zBf6IGWfZnmaetjKEBYJWC7QDQx1A91pJVJCEgieCkoIfTqkeQuePpIyu48g2FG3P1zjRF-kumhUTfSjo5qS0YiZQy0E1BMs6M11EvuxXRsHClLHoy5nLYI2Sj4zjVjYyxSHyPRPGGo9hwB34yWxzYNtPPGiqXS_dNCpi_zRZwRY4lCGrQ-hYTEWIK1Dm5OlttvC4_eiQ1dv63NiGkLRJ5kJA3bICN0fzCDY-MBqnd1cWn8YVBijVkgtaoascjL9EywDgJdeHnXK0eeOvUxHHhXJVkNqcibn8O4RQdpVU60TSA-uiu675ytIjcBHC6kTv8A8pmkj_4oypPd-F92YIJC741swkYQoeIHj8rE-ThcMUkF7KqC5VORbZTRp8HsZSqgiJcIPaouuxd1-8Rxrid3fXkE6p8bkrysPYoxWEJgh7ZFsRCPDWX-yTeJwFN0PKFP1j0F6YtlLfK5wv-c4F8ZQHA_-yc_gODicy7KmWDZgbTP07e7gEWzw4MFRrndjbDQ");


        public static final Base64URL seed = new Base64URL("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    }


    private static final class ExampleKeyMLDSA44Alt {


        public static final JWSAlgorithm ALG = JWSAlgorithm.ML_DSA_44;


        public static final Base64URL pub = new Base64URL("unH59k4RuutY-pxvu24U5h8YZD2rSVtHU5qRZsoBmBMcRPgmu9VuNOVdteXi1zNIXjnqJg_GAAxepLqA00Vc3lO0bzRIKu39VFD8Lhuk8l0V-cFEJC-zm7UihxiQMMUEmOFxe3x1ixkKZ0jqmqP3rKryx8tSbtcXyfea64QhT6XNje2SoMP6FViBDxLHBQo2dwjRls0k5a-XSQSu2OTOiHLoaWsLe8pQ5FLNfTDqmkrawDEdZyxr3oSWJAsHQxRjcIiVzZuvwxYy1zl2STiP2vy_fTBaPemkleynQzqPg7oPCyXEE8bjnJbrfWkbNNN8438e6tHPIX4l7zTuzz98YPhLjt_d6EBdT4MldsYe-Y4KLyjaGHcAlTkk9oa5RhRwW89T0z_t1DSO3dvfKLUGXh8gd1BD6Fz5MfgpF5NjoafnQEqDjsAAhrCXY4b-Y3yYJEdX4_dp3dRGdHG_rWcPmgX4JG7lCnser4f8QGnDriqiAzJYEXeS8LzUngg_0bx0lqv_KcyU5IaLISFO0xZSU5mmEPvdSoDnyAcV8pV44qhLtAvd29n0ehG259oRihtljTWeiu9V60a1N2tbZVl5mEqSK-6_xZvNYA1TCdzNctvweH24unV7U3wer9XA9Q6kvJWDVJ4oKaQsKMrCSMlteBJMRxWbGK7ddUq6F7GdQw-3j2M-qdJvVKm9UPjY9rc1lPgol25-oJxTu7nxGlbJUH-4m5pevAN6NyZ6lfhbjWTKlxkrEKZvQXs_Yf6cpXEwpI_ZJeriq1UC1XHIpRkDwdOY9MH3an4RdDl2r9vGl_IwlKPNdh_5aF3jLgn7PCit1FNJAwC8fIncAXgAlgcXIpRXdfJk4bBiO89GGccSyDh2EgXYdpG3XvNgGWy7npuSoNTE7WIyblAk13UQuO4sdCbMIuriCdyfE73mvwj15xgb07RZRQtFGlFTmnFcIdZ90zDrWXDbANntv7KCKwNvoTuv64bY3HiGbj-NQ-U9eMylWVpvr4hrXcES8c9K3PqHWADZC0iIOvlzFv4VBoc_wVflcOrL_SIoaNFCNBAZZq-2v5lAgpJTqVOtqJ_HVraoSfcKy5g45p-qULunXj6Jwq21fobQiKubBKKOZwcJFyJD7F4ACKXOrz-HIvSHMCWW_9dVrRuCpJw0s0aVFbRqopDNhu446nqb4_EDYQM1tTHMozPd_jKxRRD0sH75X8ZoToxFSpLBDbtdWcenxj-zBf6IGWfZnmaetjKEBYJWC7QDQx1A91pJVJCEgieCkoIfTqkeQuePpIyu48g2FG3P1zjRF-kumhUTfSjo5qS0YiZQy0E1BMs6M11EvuxXRsHClLHoy5nLYI2Sj4zjVjYyxSHyPRPGGo9hwB34yWxzYNtPPGiqXS_dNCpi_zRZwRY4lCGrQ-hYTEWIK1Dm5OlttvC4_eiQ1dv63NiGkLRJ5kJA3bICN0fzCDY-MBqnd1cWn8YVBijVkgtaoascjL9EywDgJdeHnXK0eeOvUxHHhXJVkNqcibn8O4RQdpVU60TSA-uiu675ytIjcBHC6kTv8A8pmkj_4oypPd-F92YIJC741swkYQoeIHj8rE-ThcMUkF7KqC5VORbZTRp8HsZSqgiJcIPaouuxd1-8Rxrid3fXkE6p8bkrysPYoxWEJgh7ZFsRCPDWX-yTeJwFN0PKFP1j0F6YtlLfK5wv-c4F8ZQHA_-yc_gODicy7KmWDZgbTP07e7gEWzw4MFRrndjbDQ");
    }


    private static final class ExampleKeyMLDSA65Alt {


        public static final JWSAlgorithm ALG = JWSAlgorithm.ML_DSA_65;


        public static final Base64URL pub = new Base64URL("QksvJn5Y1bO0TXGs_Gpla7JpUNV8YdsciAvPof6rRD8JQquL2619cIq7w1YHj22ZolInH-YsdAkeuUr7m5JkxQqIjg3-2AzV-yy9NmfmDVOevkSTAhnNT67RXbs0VaJkgCufSbzkLudVD-_91GQqVa3mk4aKRgy-wD9PyZpOMLzP-opHXlOVOWZ067galJN1h4gPbb0nvxxPWp7kPN2LDlOzt_tJxzrfvC1PjFQwNSDCm_l-Ju5X2zQtlXyJOTZSLQlCtB2C7jdyoAVwrftUXBFDkisElvgmoKlwBks23fU0tfjhwc0LVWXqhGtFQx8GGBQ-zol3e7P2EXmtIClf4KbgYq5u7Lwu848qwaItyTt7EmM2IjxVth64wHlVQruy3GXnIurcaGb_qWg764qZmteoPl5uAWwuTDX292Sa071S7GfsHFxue5lydxIYvpVUu6dyfwuExEubCovYMfz_LJd5zNTKMMatdbBJg-Qd6JPuXznqc1UYC3CccEXCLTOgg_auB6EUdG0b_cy-5bkEOHm7Wi4SDipGNig_ShzUkkot5qSqPZnd2I9IqqToi_0ep2nYLBB3ny3teW21Qpccoom3aGPt5Zl7fpzhg7Q8zsJ4sQ2SuHRCzgQ1uxYlFx21VUtHAjnFDSoMOkGyo4gH2wcLR7-z59EPPNl51pljyNefgCnMSkjrBPyz1wiET-uqi23f8Bq2TVk1jmUFxOwdfLsU7SIS30WOzvwD_gMDexUFpMlEQyL1-Y36kaTLjEWGCi2tx1FTULttQx5JpryPW6lW5oKw5RMyGpfRliYCiRyQePYqipZGoxOHpvCWhCZIN4meDY7H0RxWWQEpiyCzRQgWkOtMViwao6Jb7wZWbLNMebwLJeQJXWunk-gTEeQaMykVJobwDUiX-E_E7fSybVRTZXherY1jrvZKh8C5Gi5VADg5Vs319uN8-dVILRyOOlvjjxclmsRcn6HEvTvxd9MS7lKm2gI8BXIqhzgnTdqNGwTpmDHPV8hygqJWxWXCltBSSgY6OkGkioMAmXjZjYq_Ya9o6AE7WU_hUdm-wZmQLExwtJWEIBdDxrUxA9L9JL3weNyQtaGItPjXcheZiNBBbJTUxXwIYLnXtT1M0mHzMqGFFWXVKsN_AIdHyv4yDzY9m-tuQRfbQ_2K7r5eDOL1Tj8DZ-s8yXG74MMBqOUvlglJNgNcbuPKLRPbSDoN0E3BYkfeDgiUrXy34a5-vU-PkAWCsgAh539wJUUBxqw90V1Du7eTHFKDJEMSFYwusbPhEX4ZTwoeTHg--8Ysn4HCFWLQ00pfBCteqvMvMflcWwVfTnogcPsJb1bEFVSc3nTzhk6Ln8J-MplyS0Y5mGBEtVko_WlyeFsoDCWj4hqrgU7L-ww8vsCRSQfskH8lodiLzj0xmugiKjWUXbYq98x1zSnB9dmPy5P3UNwwMQdpebtR38N9I-jup4Bzok0-JsaOe7EORZ8ld7kAgDWa4K7BAxjc2eD540Apwxs-VLGFVkXbQgYYeDNG2tW1Xt20-XezJqZVUl6-IZXsqc7DijwNInO3fT5o8ZAcLKUUlzSlEXe8sIlHaxjLoJ-oubRtlKKUbzWOHeyxmYZSxYqQhSQj4sheedGXJEYWJ-Y5DRqB-xpy-cftxL10fdXIUhe1hWFBAoQU3b5xRY8KCytYnfLhsFF4O49xhnax3vuumLpJbCqTXpLureoKg5PvWfnpFPB0P-ZWQN35mBzqbb3ZV6U0rU55DvyXTuiZOK2Z1TxbaAd1OZMmg0cpuzewgueV-Nh_UubIqNto5RXCd7vqgqdXDUKAiWyYegYIkD4wbGMqIjxV8Oo2ggOcSj9UQPS1rD5u0rLckAzsxyty9Q5JsmKa0w8Eh7Jwe4Yob4xPVWWbJfm916avRgzDxXo5gmY7txdGFYHhlolJKdhBU9h6f0gtKEtbiUzhp4IWsqAR8riHQs7lLVEz6P537a4kL1r5FjfDf_yjJDBQmy_kdWMDqaNln-MlKK8eENjUO-qZGy0Ql4bMZtNbHXjfJUuSzapA-RqYfkqSLKgQUOW8NTDKhUk73yqCU3TQqDEKaGAoTsPscyMm7u_8QrvUK8kbc-XnxrWZ0BZJBjdinzh2w-QvjbWQ5mqFp4OMgY94__tIU8vvCUNJiYA1RdyodlfPfH5-avpxOCvBD6C7ZIDyQ-6huGEQEAb6DP8ydWIZQ8xY603DoEKKXkJWcP6CJo3nHFEdj_vcEbDQ-WESDpcQFa1fRIiGuALj-sEWcjGdSHyE8QATOcuWl4TLVzRPKAf4tCXx1zyvhJbXQu0jf0yfzVpOhPun4n-xqK4SxPBCeuJOkQ2VG9jDXWH4pnjbAcrqjveJqVti7huMXTLGuqU2uoihBw6mGqu_WSlOP2-XTEyRyvxbv2t-z9V6GPt1V9ceBukA0oGwtJqgD-q7NXFK8zhw7desI5PZMXf3nuVgbJ3xdvAlzkmm5f9RoqQS6_hqwPQEcclq1MEZ3yML5hc99TDtZWy9gGkhR0Hs3QJxxgP7bEqGFP-HjTPnJsrGaT6TjKP7qCxJlcFKLUr5AU_kxMULeUysWWtSGJ9mpxBvsyW1Juo");
    }


    private static final class ExampleKeyMLDSA87Alt {


        public static final JWSAlgorithm ALG = JWSAlgorithm.ML_DSA_87;


        public static final Base64URL pub = new Base64URL("5F_8jMc9uIXcZi5ioYzY44AylxF_pWWIFKmFtf8dt7Roz8gruSnx2Gt37RT1rhamU2h3LOUZEkEBBeBFaXWukf22Q7US8STV5gvWi4x-Mf4Bx7DcZa5HBQHMVlpuHfz8_RJWVDPEr-3VEYIeLpYQxFJ14oNt7jXO1p1--mcv0eQxi-9etuiX6LRRqiAt7QQrKq73envj9pkUbaIpqL2z_6SWRFln51IXv7yQSPmVZEPYcx-DPrMN4Q2slv_-fPZeoERcPjHoYB4TO-ahAHZP4xluJncmRB8xdR-_mm9YgGRPTnJ15X3isPEF5NsFXVDdHJyTT931NbjeKLDHTARJ8iLNLtC7j7x3XM7oyUBmW0D3EvT34AdQ6eHkzZz_JdGUXD6bylPM1PEu7nWBhW69aPJoRZVuPnvrdh8P51vdMb_i-gGBEzl7OHvVnWKmi4r3-iRauTLmn3eOLO79ITBPu4CZ6hPY6lfBgTGXovda4lEHW1Ha04-FNmnp1fmKNlUJiUGZOhWUhg-6cf5TDuXCn1jyl4r2iMy3Wlg4o1nBEumOJahYOsjawfhh_Vjir7pd5aUuAgkE9bQrwIdONb788-YRloR2jzbgCPBHEhd86-YnYHOB5W6q7hYcFym43lHb3kdNSMxoJJ6icWK4eZPmDITtbMZCPLNnbZ61CyyrWjoEnvExOB1iP6b7y8nbHnzAJeoEGLna0sxszU6V-izsJP7spwMYp1Fxa3IT9j7b9lpjM4NX-Dj5TsBxgiwkhRJIiFEHs9HE6SRnjHYU6hrwOBBGGfKuNylAvs-mninLtf9sPiCke-Sk90usNMEzwApqcGrMxv_T2OT71pqZcE4Sg8hQ2MWNHldTzZWHuDxMNGy5pYE3IT7BCDTGat_iu1xQGo7y7K3Rtnej3xpt64br8HIsT1Aw4g-QGN1bb8U-6iT9kre1tAJf6umW0-SP1MZQ2C261-r5NmOWmFEvJiU9LvaEfIUY6FZcyaVJXG__V83nMjiCxUp9tHCrLa-P_Sv3lPp8aS2ef71TLuzB14gOLKCzIWEovii0qfHRUfrJeAiwvZi3tDphKprIZYEr_qxvR0YCd4QLUqOwh_kWynztwPdo6ivRnqIRVfhLSgTEAArSrgWHFU1WC8Ckd6T5MpqJhN0x6x8qBePZGHAdYwz8qa9h7wiNLFWBrLRj5DmQLl1CVxnpVrjW33MFso4P8n060N4ghdKSSZsZozkNQ5b7O6yajYy-rSp6QpD8msb8oEX5imFKRaOcviQ2D4TRT45HJxKs63Tb9FtT1JoORzfkdv_E1bL3zSR6oYbTt2Stnpz-7kVqc8KR2N45EkFKxDkRw3IXOte0cq81xoU87S_ntf4KiVZaszuqb2XN2SgxnXBl4EDnpehPmqkD92SAlLrQcTaxaSe47G28K-8MwoVt4eeVkj4UEsSfJN7rbCH2yKl2XJx5huDaS0xn2ODQyNRmgk-5I9hXMUiZDNLvEzx4zuyrcu2d0oXFo3ZoUtVFNCB__TQCf2x27ej9GjLXLDAEi7qnl9Xfb94n0IfeVyGte3-j6NP3DWv8OrLiUjNTaLv6Fay1yzfUaU6LI86-Jd6ckloiGhg7kE0_hd-ZKakZxU1vh0Vzc6DW7MFAPky75iCZlDXoBpZjTNGo5HR-mCW_ozblu60U9zZA8bn-voANuu_hYwxh-uY1sHTFZOqp2xicnnMChz_GTm1Je8XCkICYegeiHUryEHA6T6B_L9gW8S_R4ptMD0Sv6b1KHqqKeubwKltCWPUsr2En9iYypnz06DEL5Wp8KMhrLid2AMPpLI0j1CWGJExXHpBWjfIC8vbYH4YKVl-euRo8eDcuKosb5hxUGM9Jvy1siVXUpIKpkZt2YLP5pEBP_EVOoHPh5LJomrLMpORr1wBKbEkfom7npX1g817bK4IeYmZELI8zXUUtUkx3LgNTckwjx90Vt6oVXpFEICIUDF_LAVMUftzz6JUvbwOZo8iAZqcnVslAmRXeY_ZPp5eEHFfHlsb8VQ73Rd_p8XlFf5R1WuWiUGp2TzJ-VQvj3BTdQfOwSxR9RUk4xjqNabLqTFcQ7As246bHJXH6XVnd4DbEIDPfNa8FaWb_DNEgQAiXGqa6n7l7aFq5_6Kp0XeBBM0sOzJt4fy8JC6U0DEcMnWxKFDtMM7q06LubQYFCEEdQ5b1Qh2LbQZ898tegmeF--EZ4F4hvYebZPV8sM0ZcsKBXyCr585qs00PRxr0S6rReekGRBIvXzMojmid3dxc6DPpdV3x5zxlxaIBxO3i_6axknSSdxnS04_bemWqQ3CLf6mpSqfTIQJT1407GB4QINAAC9Ch3AXUR_n1jr64TGWzbIr8uDcnoVCJlOgmlXpmOwubigAzJattbWRi7k4QYBnA3_4QMjt73n2Co4-F_Qh4boYLpmwWG2SwcIw2PeXGr2LY2zwkPR4bcSyx1Z6UK5trQpWlpQCxgsvV_RvGzpN22RtHoihPH74K0cBIzCz7tK-jqeuWl1A7af7KmQ66fpRBr5ykTLOsa17WblkcIB_jDvqKfEcdxhPWJUwmOo4TIQS-xH8arLOy_NQFG2m14_yxwUemXC-QxLUYi6_FIcqwPBKjCdpQtadRdyftQSKO0SP-GxUvamMZzWI780rXuOBkq5kyYLy9QF9bf_-bL6QLpe1WMCQlOeXZaCPoncgYoT0WZ17jB52Xb2lPWsyXYK54npszkbKJ4OIqfvF8xqRXcVe22VwJuqT9Uy4-4KKQgQ7TXla7Gdm2H7mKl8YXQlsGCT2Ypc8O4t0Sfw7qYAuaDGf752Hbm3fl1bupcB2huIPlIaDP6IRR9XvTYIW2flbwYfhKLmoVKnG85uUi2qtqCjPOIuU3-peT0othfmwKQXaoOqO-V4r6wPL1VHxVFtIYmEdVt0RccUOvpOVR_OAHG9uHOzTmueK5557Qxp0ojtZCHyN-hgoMZJLrvdKkTCxPNo2-mZQbHoVh2FnThZ9JbO49dB8lKXP4_MU5xAnjXMgKXtbfI8w6ZWATE_XWgf2VQMUpGp4wpy44yWQTxHxh_4T9540BGwG0FU0bkgrwA_erseGZnepqdmz5_ScCs84O5Xr5MbYhJLCGGxY6O5GqS-ooB2w0Mt87KbbE4bpYje9CAHH8FX3pDrJyLsyasA3zxmk4OmGpG7Z70ofONJtHRe56R5287vFmuazEEutXn81kNzB-3aJT1ga3vnWZw4CSvFKoWYSA7auLgrHSHFZdITfOrgtmQmGbFhM9kSBdY1UCnpzf65oos3PZWRa2twfUxxLAnPNtrxpRGyvtsapw7ljUagZmuyh3hLCjhAxYmnoE1dbyIWvpCqSlEtVjL1yb_nuLEzgvmZuV02fHxGuWgHTOMVGXpf81Rce3eoBK3lapW1wkzezlk3tcA2bZOtA9qbxdsbVR37kemzQ9K1e3Y0OWhtSj");
    }


    private static final Date EXP = DateUtils.fromSecondsSinceEpoch(13_000_000L);
    private static final Date NBF = DateUtils.fromSecondsSinceEpoch(12_000_000L);
    private static final Date IAT = DateUtils.fromSecondsSinceEpoch(11_000_000L);
    private static final KeyRevocation KEY_REVOCATION = new KeyRevocation(DateUtils.fromSecondsSinceEpoch(13_500_000L), KeyRevocation.Reason.UNSPECIFIED);



    public void testKeySizes() {

        assertEquals(2560, new MLDSAKey.Builder(ExampleKeyMLDSA44.ALG, ExampleKeyMLDSA44.pub).build().size());
        assertEquals(2560, new MLDSAKey.Builder(ExampleKeyMLDSA44Alt.ALG, ExampleKeyMLDSA44Alt.pub).build().size());
        assertEquals(4032, new MLDSAKey.Builder(ExampleKeyMLDSA65Alt.ALG, ExampleKeyMLDSA65Alt.pub).build().size());
        assertEquals(4896, new MLDSAKey.Builder(ExampleKeyMLDSA87Alt.ALG, ExampleKeyMLDSA87Alt.pub).build().size());
    }


    public void testSupportedCurvesConstant() {

        assertTrue(MLDSAKey.SUPPORTED_ALGORITHMS.contains(JWSAlgorithm.ML_DSA_44));
        assertTrue(MLDSAKey.SUPPORTED_ALGORITHMS.contains(JWSAlgorithm.ML_DSA_65));
        assertTrue(MLDSAKey.SUPPORTED_ALGORITHMS.contains(JWSAlgorithm.ML_DSA_87));
        assertTrue(MLDSAKey.SUPPORTED_ALGORITHMS.contains(JWSAlgorithm.Dilithium2));
        assertTrue(MLDSAKey.SUPPORTED_ALGORITHMS.contains(JWSAlgorithm.Dilithium3));
        assertTrue(MLDSAKey.SUPPORTED_ALGORITHMS.contains(JWSAlgorithm.Dilithium5));
        assertEquals(6, MLDSAKey.SUPPORTED_ALGORITHMS.size());
    }


    public void testUnknownAlgorithm() {

        try {
            new MLDSAKey.Builder(new JWSAlgorithm("unknown"), ExampleKeyMLDSA44.pub).build();
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals("Unknown / unsupported alg: unknown", e.getMessage());
        }
    }


    public void testAltMLDSAKeyParamLengths() {

        assertEquals(1312, ExampleKeyMLDSA44Alt.pub.decode().length);

        assertEquals(1952, ExampleKeyMLDSA65Alt.pub.decode().length);

        assertEquals(2592, ExampleKeyMLDSA87Alt.pub.decode().length);
    }


    public void testFullPrivateConstructorAndSerialization()
            throws Exception {

        URI x5u = new URI("http://example.com/jwk.json");
        Base64URL x5t = new Base64URL("abc");
        Base64URL x5t256 = new Base64URL("abc256");
        List<Base64> x5c = null;

        Set<KeyOperation> ops = null;

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        MLDSAKey key = new MLDSAKey(ExampleKeyMLDSA44.ALG, ExampleKeyMLDSA44.pub, ExampleKeyMLDSA44.seed,
                KeyUse.SIGNATURE, ops, "1", x5u, x5t, x5t256, x5c, EXP, NBF, IAT, KEY_REVOCATION, keyStore);

        assertTrue(key instanceof AsymmetricJWK);

        // Test getters
        assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
        assertNull(key.getKeyOperations());
        assertEquals(JWSAlgorithm.ML_DSA_44, key.getAlgorithm());
        assertEquals("1", key.getKeyID());
        assertEquals(x5u.toString(), key.getX509CertURL().toString());
        assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
        assertEquals(x5t256.toString(), key.getX509CertSHA256Thumbprint().toString());
        assertNull(key.getX509CertChain());
        assertNull(key.getParsedX509CertChain());
        assertEquals(EXP, key.getExpirationTime());
        assertEquals(NBF, key.getNotBeforeTime());
        assertEquals(IAT, key.getIssueTime());
        assertEquals(KEY_REVOCATION, key.getKeyRevocation());
        assertEquals(keyStore, key.getKeyStore());

        assertEquals(ExampleKeyMLDSA44.ALG, key.getAlgorithm());
        assertEquals(MLDSAUtils.base64toPublicKey(ExampleKeyMLDSA44.pub, ExampleKeyMLDSA44.ALG), key.toPublicKey());
        assertEquals(ExampleKeyMLDSA44.seed, key.getSeed());

        assertTrue(key.isPrivate());


        String jwkString = JSONObjectUtils.toJSONString(key.toJSONObject());

        key = MLDSAKey.parse(jwkString);

        // Test getters
        assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
        assertNull(key.getKeyOperations());
        assertEquals(JWSAlgorithm.ML_DSA_44, key.getAlgorithm());
        assertEquals("1", key.getKeyID());
        assertEquals(EXP, key.getExpirationTime());
        assertEquals(NBF, key.getNotBeforeTime());
        assertEquals(IAT, key.getIssueTime());
        assertEquals(KEY_REVOCATION, key.getKeyRevocation());
        assertNull(key.getKeyStore());

        assertEquals(ExampleKeyMLDSA44.ALG, key.getAlgorithm());
        assertEquals(MLDSAUtils.base64toPublicKey(ExampleKeyMLDSA44.pub, ExampleKeyMLDSA44.ALG), key.toPublicKey());
        assertEquals(ExampleKeyMLDSA44.seed, key.getSeed());

        assertTrue(key.isPrivate());


        // Test conversion to public JWK

        key = key.toPublicJWK();

        assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
        assertNull(key.getKeyOperations());
        assertEquals(JWSAlgorithm.ML_DSA_44, key.getAlgorithm());
        assertEquals("1", key.getKeyID());
        assertEquals(x5u.toString(), key.getX509CertURL().toString());
        assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
        assertEquals(x5t256.toString(), key.getX509CertSHA256Thumbprint().toString());
        assertNull(key.getX509CertChain());
        assertNull(key.getParsedX509CertChain());
        assertEquals(EXP, key.getExpirationTime());
        assertEquals(NBF, key.getNotBeforeTime());
        assertEquals(IAT, key.getIssueTime());
        assertEquals(KEY_REVOCATION, key.getKeyRevocation());
        assertNull(key.getKeyStore());

        assertEquals(ExampleKeyMLDSA44.ALG, key.getAlgorithm());
        assertEquals(MLDSAUtils.base64toPublicKey(ExampleKeyMLDSA44.pub, ExampleKeyMLDSA44.ALG), key.toPublicKey());
        assertNull(key.getSeed());

        assertFalse(key.isPrivate());
    }


    public void testPrivateConstructorAndSerializationWithOps()
            throws Exception {

        URI x5u = new URI("http://example.com/jwk.json");
        Base64URL x5t = new Base64URL("abc");
        Base64URL x5t256 = new Base64URL("abc256");
        List<Base64> x5c = null;

        KeyUse use = null;
        Set<KeyOperation> ops = new LinkedHashSet<>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY));

        MLDSAKey key = new MLDSAKey(ExampleKeyMLDSA44.ALG, ExampleKeyMLDSA44.pub, ExampleKeyMLDSA44.seed,
                use, ops, "1", x5u, x5t, x5t256, x5c, EXP, NBF, IAT, KEY_REVOCATION, null);

        // Test getters
        assertNull(key.getKeyUse());
        assertTrue(key.getKeyOperations().contains(KeyOperation.SIGN));
        assertTrue(key.getKeyOperations().contains(KeyOperation.VERIFY));
        assertEquals(2, key.getKeyOperations().size());
        assertEquals(JWSAlgorithm.ML_DSA_44, key.getAlgorithm());
        assertEquals("1", key.getKeyID());
        assertEquals(x5u.toString(), key.getX509CertURL().toString());
        assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
        assertEquals(x5t256.toString(), key.getX509CertSHA256Thumbprint().toString());
        assertNull(key.getX509CertChain());
        assertNull(key.getParsedX509CertChain());
        assertEquals(EXP, key.getExpirationTime());
        assertEquals(NBF, key.getNotBeforeTime());
        assertEquals(IAT, key.getIssueTime());
        assertEquals(KEY_REVOCATION, key.getKeyRevocation());
        assertNull(key.getKeyStore());

        assertEquals(ExampleKeyMLDSA44.ALG, key.getAlgorithm());
        assertEquals(MLDSAUtils.base64toPublicKey(ExampleKeyMLDSA44.pub, ExampleKeyMLDSA44.ALG), key.toPublicKey());
        assertEquals(ExampleKeyMLDSA44.seed, key.getSeed());

        assertTrue(key.isPrivate());


        String jwkString = JSONObjectUtils.toJSONString( key.toJSONObject());

        key = MLDSAKey.parse(jwkString);

        // Test getters
        assertNull(key.getKeyUse());
        assertTrue(key.getKeyOperations().contains(KeyOperation.SIGN));
        assertTrue(key.getKeyOperations().contains(KeyOperation.VERIFY));
        assertEquals(2, key.getKeyOperations().size());
        assertEquals(JWSAlgorithm.ML_DSA_44, key.getAlgorithm());
        assertEquals("1", key.getKeyID());
        assertEquals(EXP, key.getExpirationTime());
        assertEquals(NBF, key.getNotBeforeTime());
        assertEquals(IAT, key.getIssueTime());
        assertEquals(KEY_REVOCATION, key.getKeyRevocation());
        assertNull(key.getKeyStore());

        assertEquals(MLDSAUtils.base64toPublicKey(ExampleKeyMLDSA44.pub, ExampleKeyMLDSA44.ALG), key.toPublicKey());
        assertEquals(ExampleKeyMLDSA44.seed, key.getSeed());

        assertTrue(key.isPrivate());


        // Test conversion to public JWK

        key = key.toPublicJWK();

        assertNull(key.getKeyUse());
        assertTrue(key.getKeyOperations().contains(KeyOperation.SIGN));
        assertTrue(key.getKeyOperations().contains(KeyOperation.VERIFY));
        assertEquals(2, key.getKeyOperations().size());
        assertEquals(JWSAlgorithm.ML_DSA_44, key.getAlgorithm());
        assertEquals("1", key.getKeyID());
        assertEquals(x5u.toString(), key.getX509CertURL().toString());
        assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
        assertEquals(x5t256.toString(), key.getX509CertSHA256Thumbprint().toString());
        assertNull(key.getX509CertChain());
        assertNull(key.getParsedX509CertChain());
        assertEquals(EXP, key.getExpirationTime());
        assertEquals(NBF, key.getNotBeforeTime());
        assertEquals(IAT, key.getIssueTime());
        assertEquals(KEY_REVOCATION, key.getKeyRevocation());
        assertNull(key.getKeyStore());

        assertEquals(ExampleKeyMLDSA44.ALG, key.getAlgorithm());
        assertEquals(MLDSAUtils.base64toPublicKey(ExampleKeyMLDSA44.pub, ExampleKeyMLDSA44.ALG), key.toPublicKey());
        assertNull(key.getSeed());

        assertFalse(key.isPrivate());
    }


    public void testBuilder()
            throws Exception {

        URI x5u = new URI("http://example.com/jwk.json");
        Base64URL x5t = new Base64URL("abc");
        List<Base64> x5c = null;

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        MLDSAKey key = new MLDSAKey.Builder(JWSAlgorithm.ML_DSA_44, ExampleKeyMLDSA44.pub)
                .seed(ExampleKeyMLDSA44.seed)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("1")
                .x509CertURL(x5u)
                .x509CertThumbprint(x5t)
                .x509CertChain(x5c)
                .expirationTime(EXP)
                .notBeforeTime(NBF)
                .issueTime(IAT)
                .keyRevocation(KEY_REVOCATION)
                .keyStore(keyStore)
                .build();

        // Test getters
        assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
        assertEquals(JWSAlgorithm.ML_DSA_44, key.getAlgorithm());
        assertEquals("1", key.getKeyID());
        assertEquals(x5u.toString(), key.getX509CertURL().toString());
        assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
        assertNull(key.getX509CertChain());
        assertNull(key.getParsedX509CertChain());
        assertEquals(EXP, key.getExpirationTime());
        assertEquals(NBF, key.getNotBeforeTime());
        assertEquals(IAT, key.getIssueTime());
        assertEquals(KEY_REVOCATION, key.getKeyRevocation());
        assertEquals(keyStore, key.getKeyStore());

        assertEquals(ExampleKeyMLDSA44.ALG, key.getAlgorithm());
        assertEquals(MLDSAUtils.base64toPublicKey(ExampleKeyMLDSA44.pub, ExampleKeyMLDSA44.ALG), key.toPublicKey());
        assertEquals(ExampleKeyMLDSA44.seed, key.getSeed());

        assertTrue(key.isPrivate());


        String jwkString = JSONObjectUtils.toJSONString( key.toJSONObject());

        key = MLDSAKey.parse(jwkString);

        // Test getters
        assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
        assertEquals(JWSAlgorithm.ML_DSA_44, key.getAlgorithm());
        assertEquals("1", key.getKeyID());
        assertEquals(EXP, key.getExpirationTime());
        assertEquals(NBF, key.getNotBeforeTime());
        assertEquals(IAT, key.getIssueTime());
        assertEquals(KEY_REVOCATION, key.getKeyRevocation());
        assertNull(key.getKeyStore());

        assertEquals(ExampleKeyMLDSA44.ALG, key.getAlgorithm());
        assertEquals(MLDSAUtils.base64toPublicKey(ExampleKeyMLDSA44.pub, ExampleKeyMLDSA44.ALG), key.toPublicKey());
        assertEquals(ExampleKeyMLDSA44.seed, key.getSeed());

        assertTrue(key.isPrivate());


        // Test conversion to public JWK

        key = key.toPublicJWK();

        assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
        assertEquals(JWSAlgorithm.ML_DSA_44, key.getAlgorithm());
        assertEquals("1", key.getKeyID());
        assertEquals(x5u.toString(), key.getX509CertURL().toString());
        assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
        assertNull(key.getX509CertChain());
        assertNull(key.getParsedX509CertChain());
        assertEquals(EXP, key.getExpirationTime());
        assertEquals(NBF, key.getNotBeforeTime());
        assertEquals(IAT, key.getIssueTime());
        assertEquals(KEY_REVOCATION, key.getKeyRevocation());
        assertNull(key.getKeyStore());

        assertEquals(ExampleKeyMLDSA44.ALG, key.getAlgorithm());
        assertEquals(MLDSAUtils.base64toPublicKey(ExampleKeyMLDSA44.pub, ExampleKeyMLDSA44.ALG), key.toPublicKey());
        assertNull(key.getSeed());

        assertFalse(key.isPrivate());
    }


    public void testCopyBuilder()
            throws Exception {

        URI x5u = new URI("http://example.com/jwk.json");
        Base64URL x5t = new Base64URL("abc");
        List<Base64> x5c = null;

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        MLDSAKey key = new MLDSAKey.Builder(JWSAlgorithm.ML_DSA_44, ExampleKeyMLDSA44.pub)
                .seed(ExampleKeyMLDSA44.seed)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("1")
                .x509CertURL(x5u)
                .x509CertThumbprint(x5t)
                .x509CertChain(x5c)
                .expirationTime(EXP)
                .notBeforeTime(NBF)
                .issueTime(IAT)
                .keyRevocation(KEY_REVOCATION)
                .keyStore(keyStore)
                .build();

        // Copy
        key = new MLDSAKey.Builder(key).build();

        // Test getters
        assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
        assertEquals(JWSAlgorithm.ML_DSA_44, key.getAlgorithm());
        assertEquals("1", key.getKeyID());
        assertEquals(x5u.toString(), key.getX509CertURL().toString());
        assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
        assertNull(key.getX509CertChain());
        assertNull(key.getParsedX509CertChain());
        assertEquals(EXP, key.getExpirationTime());
        assertEquals(NBF, key.getNotBeforeTime());
        assertEquals(IAT, key.getIssueTime());
        assertEquals(KEY_REVOCATION, key.getKeyRevocation());
        assertEquals(keyStore, key.getKeyStore());

        assertEquals(ExampleKeyMLDSA44.ALG, key.getAlgorithm());
        assertEquals(MLDSAUtils.base64toPublicKey(ExampleKeyMLDSA44.pub, ExampleKeyMLDSA44.ALG), key.toPublicKey());
        assertEquals(ExampleKeyMLDSA44.seed, key.getSeed());

        assertTrue(key.isPrivate());
    }


    public void testBuilder_privateKeyNull()
            throws JOSEException {

        MLDSAKey mldsaJWK = new MLDSAKeyGenerator(JWSAlgorithm.ML_DSA_44).generate();

        MLDSAKey out = new MLDSAKey.Builder(JWSAlgorithm.ML_DSA_44, mldsaJWK.toPublicKey())
                .privateKey((PrivateKey) null)
                .build();

        assertFalse(out.isPrivate());
        assertNull(out.getSeed());
        assertNull(out.toPrivateKey());
    }


    public void testBuilder_privateKey_setThenClear()
            throws JOSEException {

        MLDSAKey mldsaJWK = new MLDSAKeyGenerator(JWSAlgorithm.ML_DSA_44).generate();

        MLDSAKey out = new MLDSAKey.Builder(JWSAlgorithm.ML_DSA_44, mldsaJWK.toPublicKey())
                .privateKey(new PrivateKey() {
                    @Override
                    public String getAlgorithm() {
                        return "ML-DSA-44";
                    }

                    @Override
                    public String getFormat() {
                        return "";
                    }

                    @Override
                    public byte[] getEncoded() {
                        return new byte[0];
                    }
                })
                .privateKey((PrivateKey) null)
                .build();

        assertFalse(out.isPrivate());
        assertNull(out.getSeed());
        assertNull(out.toPrivateKey());
    }


    public void testBuilder_privateKey_illegalAlgorithm()
            throws JOSEException {

        MLDSAKey mldsaJWK = new MLDSAKeyGenerator(JWSAlgorithm.ML_DSA_44).generate();

        try {
            new MLDSAKey.Builder(JWSAlgorithm.ML_DSA_44, mldsaJWK.toPublicKey())
                    .privateKey(new PrivateKey() {
                        @Override
                        public String getAlgorithm() {
                            return "RSA";
                        }

                        @Override
                        public String getFormat() {
                            return "";
                        }

                        @Override
                        public byte[] getEncoded() {
                            return new byte[0];
                        }
                    });
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals("The private key algorithm must be ML-DSA-44, ML-DSA-65, ML-DSA-87, Dilithium2, Dilithium3 or Dilithium5", e.getMessage());
        }
    }


    public void testMLDSA44ExportAndImport()
            throws Exception {

        // Public + private

        MLDSAKey key = new MLDSAKey.Builder(ExampleKeyMLDSA44.ALG, ExampleKeyMLDSA44.pub).seed(ExampleKeyMLDSA44.seed).build();

        // Export
        KeyPair pair = key.toKeyPair();

        PublicKey pub = (PublicKey) pair.getPublic();
        assertEquals("ML-DSA-44", pub.getAlgorithm());

        PrivateKey priv = (PrivateKey) pair.getPrivate();
        assertEquals("ML-DSA-44", priv.getAlgorithm());

        // Import
        key = new MLDSAKey.Builder(JWSAlgorithm.ML_DSA_44, pub).privateKey(priv).build();
        assertEquals(JWSAlgorithm.ML_DSA_44, key.getAlgorithm());
        assertEquals(ExampleKeyMLDSA44.ALG, key.getAlgorithm());
        assertEquals(MLDSAUtils.base64toPublicKey(ExampleKeyMLDSA44.pub, ExampleKeyMLDSA44.ALG), key.toPublicKey());

        assertTrue(key.isPrivate());
    }


    public void testMLDSA44AltExportAndImport()
            throws Exception {

        MLDSAKey key = new MLDSAKey.Builder(ExampleKeyMLDSA44Alt.ALG, ExampleKeyMLDSA44Alt.pub).build();

        // Export
        KeyPair pair = key.toKeyPair();

        PublicKey pub = (PublicKey) pair.getPublic();
        assertEquals("ML-DSA-44", pub.getAlgorithm());
        assertEquals(MLDSAUtils.base64toPublicKey(ExampleKeyMLDSA44Alt.pub, ExampleKeyMLDSA44Alt.ALG), pub);

        // Import
        key = new MLDSAKey.Builder(ExampleKeyMLDSA44Alt.ALG, pub).build();
        assertEquals(JWSAlgorithm.ML_DSA_44, key.getAlgorithm());
        assertEquals(MLDSAUtils.base64toPublicKey(ExampleKeyMLDSA44Alt.pub, ExampleKeyMLDSA44Alt.ALG), key.toPublicKey());

        assertFalse(key.isPrivate());
    }


    public void testMLDSA65AltExportAndImport()
            throws Exception {

        MLDSAKey key = new MLDSAKey.Builder(ExampleKeyMLDSA65Alt.ALG, ExampleKeyMLDSA65Alt.pub).build();

        // Export
        KeyPair pair = key.toKeyPair();

        PublicKey pub = (PublicKey) pair.getPublic();
        assertEquals("ML-DSA-65", pub.getAlgorithm());
        assertEquals(MLDSAUtils.base64toPublicKey(ExampleKeyMLDSA65Alt.pub, ExampleKeyMLDSA65Alt.ALG), key.toPublicKey());

        // Import
        key = new MLDSAKey.Builder(ExampleKeyMLDSA65Alt.ALG, pub).build();
        assertEquals(JWSAlgorithm.ML_DSA_65, key.getAlgorithm());
        assertEquals(MLDSAUtils.base64toPublicKey(ExampleKeyMLDSA65Alt.pub, ExampleKeyMLDSA65Alt.ALG), key.toPublicKey());

        assertFalse(key.isPrivate());
    }


    public void testMLDSA87AltExportAndImport()
            throws Exception {

        MLDSAKey key = new MLDSAKey.Builder(ExampleKeyMLDSA87Alt.ALG, ExampleKeyMLDSA87Alt.pub).build();

        // Export
        KeyPair pair = key.toKeyPair();

        PublicKey pub = (PublicKey) pair.getPublic();
        assertEquals("ML-DSA-87", pub.getAlgorithm());
        assertEquals(MLDSAUtils.base64toPublicKey(ExampleKeyMLDSA87Alt.pub, ExampleKeyMLDSA87Alt.ALG), key.toPublicKey());

        // Import
        key = new MLDSAKey.Builder(ExampleKeyMLDSA87Alt.ALG, pub).build();
        assertEquals(JWSAlgorithm.ML_DSA_87, key.getAlgorithm());
        assertEquals(MLDSAUtils.base64toPublicKey(ExampleKeyMLDSA87Alt.pub, ExampleKeyMLDSA87Alt.ALG), key.toPublicKey());

        assertFalse(key.isPrivate());
    }


    public void testKeyUseConsistentWithOps() {

        KeyUse use = KeyUse.SIGNATURE;

        Set<KeyOperation> ops = new HashSet<>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY));

        JWK jwk = new MLDSAKey(ExampleKeyMLDSA44.ALG, ExampleKeyMLDSA44.pub, use, ops, null, null, null, null, null, null);
        assertEquals(use, jwk.getKeyUse());
        assertEquals(ops, jwk.getKeyOperations());

        jwk = new MLDSAKey.Builder(ExampleKeyMLDSA44.ALG, ExampleKeyMLDSA44.pub)
                .keyUse(use)
                .keyOperations(ops)
                .build();
        assertEquals(use, jwk.getKeyUse());
        assertEquals(ops, jwk.getKeyOperations());
    }


    public void testRejectKeyUseNotConsistentWithOps() {

        KeyUse use = KeyUse.SIGNATURE;

        Set<KeyOperation> ops = new HashSet<>(Arrays.asList(KeyOperation.ENCRYPT, KeyOperation.DECRYPT));

        try {
            new MLDSAKey.Builder(ExampleKeyMLDSA44.ALG, ExampleKeyMLDSA44.pub)
                    .keyUse(use)
                    .keyOperations(ops)
                    .build();
            fail();
        } catch (IllegalStateException e) {
            assertEquals("The key use \"use\" and key options \"key_ops\" parameters are not consistent, see RFC 7517, section 4.3", e.getMessage());
        }
    }


    public void testDraftExampleKey()
            throws Exception {

        // See http://tools.ietf.org/html/rfc7520#section-3.2

        String json = "{" +
                "\"kty\":\"AKP\"," +
                "\"kid\":\"T4xl70S7MT6Zeq6r9V9fPJGVn76wfnXJ21-gyo0Gu6o\"," +
                "\"use\":\"sig\"," +
                "\"alg\":\"ML-DSA-44\"," +
                "\"pub\":\"unH59k4RuutY-pxvu24U5h8YZD2rSVtHU5qRZsoBmBMcRPgmu9VuNOVdteXi1zNIXjnqJg_GAAxepLqA00Vc3lO0bzRIKu39VFD8Lhuk8l0V-cFEJC-zm7UihxiQMMUEmOFxe3x1ixkKZ0jqmqP3rKryx8tSbtcXyfea64QhT6XNje2SoMP6FViBDxLHBQo2dwjRls0k5a-XSQSu2OTOiHLoaWsLe8pQ5FLNfTDqmkrawDEdZyxr3oSWJAsHQxRjcIiVzZuvwxYy1zl2STiP2vy_fTBaPemkleynQzqPg7oPCyXEE8bjnJbrfWkbNNN8438e6tHPIX4l7zTuzz98YPhLjt_d6EBdT4MldsYe-Y4KLyjaGHcAlTkk9oa5RhRwW89T0z_t1DSO3dvfKLUGXh8gd1BD6Fz5MfgpF5NjoafnQEqDjsAAhrCXY4b-Y3yYJEdX4_dp3dRGdHG_rWcPmgX4JG7lCnser4f8QGnDriqiAzJYEXeS8LzUngg_0bx0lqv_KcyU5IaLISFO0xZSU5mmEPvdSoDnyAcV8pV44qhLtAvd29n0ehG259oRihtljTWeiu9V60a1N2tbZVl5mEqSK-6_xZvNYA1TCdzNctvweH24unV7U3wer9XA9Q6kvJWDVJ4oKaQsKMrCSMlteBJMRxWbGK7ddUq6F7GdQw-3j2M-qdJvVKm9UPjY9rc1lPgol25-oJxTu7nxGlbJUH-4m5pevAN6NyZ6lfhbjWTKlxkrEKZvQXs_Yf6cpXEwpI_ZJeriq1UC1XHIpRkDwdOY9MH3an4RdDl2r9vGl_IwlKPNdh_5aF3jLgn7PCit1FNJAwC8fIncAXgAlgcXIpRXdfJk4bBiO89GGccSyDh2EgXYdpG3XvNgGWy7npuSoNTE7WIyblAk13UQuO4sdCbMIuriCdyfE73mvwj15xgb07RZRQtFGlFTmnFcIdZ90zDrWXDbANntv7KCKwNvoTuv64bY3HiGbj-NQ-U9eMylWVpvr4hrXcES8c9K3PqHWADZC0iIOvlzFv4VBoc_wVflcOrL_SIoaNFCNBAZZq-2v5lAgpJTqVOtqJ_HVraoSfcKy5g45p-qULunXj6Jwq21fobQiKubBKKOZwcJFyJD7F4ACKXOrz-HIvSHMCWW_9dVrRuCpJw0s0aVFbRqopDNhu446nqb4_EDYQM1tTHMozPd_jKxRRD0sH75X8ZoToxFSpLBDbtdWcenxj-zBf6IGWfZnmaetjKEBYJWC7QDQx1A91pJVJCEgieCkoIfTqkeQuePpIyu48g2FG3P1zjRF-kumhUTfSjo5qS0YiZQy0E1BMs6M11EvuxXRsHClLHoy5nLYI2Sj4zjVjYyxSHyPRPGGo9hwB34yWxzYNtPPGiqXS_dNCpi_zRZwRY4lCGrQ-hYTEWIK1Dm5OlttvC4_eiQ1dv63NiGkLRJ5kJA3bICN0fzCDY-MBqnd1cWn8YVBijVkgtaoascjL9EywDgJdeHnXK0eeOvUxHHhXJVkNqcibn8O4RQdpVU60TSA-uiu675ytIjcBHC6kTv8A8pmkj_4oypPd-F92YIJC741swkYQoeIHj8rE-ThcMUkF7KqC5VORbZTRp8HsZSqgiJcIPaouuxd1-8Rxrid3fXkE6p8bkrysPYoxWEJgh7ZFsRCPDWX-yTeJwFN0PKFP1j0F6YtlLfK5wv-c4F8ZQHA_-yc_gODicy7KmWDZgbTP07e7gEWzw4MFRrndjbDQ\"," +
                "\"seed\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"" +
                "}";

        MLDSAKey jwk = MLDSAKey.parse(json);

        assertEquals(KeyType.AKP, jwk.getKeyType());
        assertEquals("T4xl70S7MT6Zeq6r9V9fPJGVn76wfnXJ21-gyo0Gu6o", jwk.getKeyID());
        assertEquals(KeyUse.SIGNATURE, jwk.getKeyUse());
        assertEquals(JWSAlgorithm.ML_DSA_44, jwk.getAlgorithm());

        Base64URL pubBase64 = JSONObjectUtils.getBase64URL(JSONObjectUtils.parse(json), JWKParameterNames.AKP_PUBLIC_KEY);

        assertEquals(MLDSAUtils.base64toPublicKey(pubBase64, JWSAlgorithm.ML_DSA_44), jwk.toPublicKey());

        assertEquals("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", jwk.getSeed().toString());

        // Convert to Java ML-DSA key object
        PublicKey publicKey = jwk.toPublicKey();
        PrivateKey privateKey = jwk.toPrivateKey();

        jwk = new MLDSAKey.Builder(JWSAlgorithm.ML_DSA_44, publicKey).privateKey(privateKey).build();

        assertEquals(MLDSAUtils.base64toPublicKey(pubBase64, JWSAlgorithm.ML_DSA_44), jwk.toPublicKey());
    }


//    public void testThumbprint()
//            throws Exception {
//
//        MLDSAKey mldsaKey = new MLDSAKey.Builder(ExampleKeyMLDSA44.ALG, ExampleKeyMLDSA44.pub).build();
//
//        Base64URL thumbprint = mldsaKey.computeThumbprint();
//
//        assertEquals(256 / 8, thumbprint.decode().length);
//
//        String orderedJSON = "{\"alg\":\"ML-DSA-44\",\"kty\":\"AKP\",\"pub\":\"unH59k4RuutY-pxvu24U5h8YZD2rSVtHU5qRZsoBmBMcRPgmu9VuNOVdteXi1zNIXjnqJg_GAAxepLqA00Vc3lO0bzRIKu39VFD8Lhuk8l0V-cFEJC-zm7UihxiQMMUEmOFxe3x1ixkKZ0jqmqP3rKryx8tSbtcXyfea64QhT6XNje2SoMP6FViBDxLHBQo2dwjRls0k5a-XSQSu2OTOiHLoaWsLe8pQ5FLNfTDqmkrawDEdZyxr3oSWJAsHQxRjcIiVzZuvwxYy1zl2STiP2vy_fTBaPemkleynQzqPg7oPCyXEE8bjnJbrfWkbNNN8438e6tHPIX4l7zTuzz98YPhLjt_d6EBdT4MldsYe-Y4KLyjaGHcAlTkk9oa5RhRwW89T0z_t1DSO3dvfKLUGXh8gd1BD6Fz5MfgpF5NjoafnQEqDjsAAhrCXY4b-Y3yYJEdX4_dp3dRGdHG_rWcPmgX4JG7lCnser4f8QGnDriqiAzJYEXeS8LzUngg_0bx0lqv_KcyU5IaLISFO0xZSU5mmEPvdSoDnyAcV8pV44qhLtAvd29n0ehG259oRihtljTWeiu9V60a1N2tbZVl5mEqSK-6_xZvNYA1TCdzNctvweH24unV7U3wer9XA9Q6kvJWDVJ4oKaQsKMrCSMlteBJMRxWbGK7ddUq6F7GdQw-3j2M-qdJvVKm9UPjY9rc1lPgol25-oJxTu7nxGlbJUH-4m5pevAN6NyZ6lfhbjWTKlxkrEKZvQXs_Yf6cpXEwpI_ZJeriq1UC1XHIpRkDwdOY9MH3an4RdDl2r9vGl_IwlKPNdh_5aF3jLgn7PCit1FNJAwC8fIncAXgAlgcXIpRXdfJk4bBiO89GGccSyDh2EgXYdpG3XvNgGWy7npuSoNTE7WIyblAk13UQuO4sdCbMIuriCdyfE73mvwj15xgb07RZRQtFGlFTmnFcIdZ90zDrWXDbANntv7KCKwNvoTuv64bY3HiGbj-NQ-U9eMylWVpvr4hrXcES8c9K3PqHWADZC0iIOvlzFv4VBoc_wVflcOrL_SIoaNFCNBAZZq-2v5lAgpJTqVOtqJ_HVraoSfcKy5g45p-qULunXj6Jwq21fobQiKubBKKOZwcJFyJD7F4ACKXOrz-HIvSHMCWW_9dVrRuCpJw0s0aVFbRqopDNhu446nqb4_EDYQM1tTHMozPd_jKxRRD0sH75X8ZoToxFSpLBDbtdWcenxj-zBf6IGWfZnmaetjKEBYJWC7QDQx1A91pJVJCEgieCkoIfTqkeQuePpIyu48g2FG3P1zjRF-kumhUTfSjo5qS0YiZQy0E1BMs6M11EvuxXRsHClLHoy5nLYI2Sj4zjVjYyxSHyPRPGGo9hwB34yWxzYNtPPGiqXS_dNCpi_zRZwRY4lCGrQ-hYTEWIK1Dm5OlttvC4_eiQ1dv63NiGkLRJ5kJA3bICN0fzCDY-MBqnd1cWn8YVBijVkgtaoascjL9EywDgJdeHnXK0eeOvUxHHhXJVkNqcibn8O4RQdpVU60TSA-uiu675ytIjcBHC6kTv8A8pmkj_4oypPd-F92YIJC741swkYQoeIHj8rE-ThcMUkF7KqC5VORbZTRp8HsZSqgiJcIPaouuxd1-8Rxrid3fXkE6p8bkrysPYoxWEJgh7ZFsRCPDWX-yTeJwFN0PKFP1j0F6YtlLfK5wv-c4F8ZQHA_-yc_gODicy7KmWDZgbTP07e7gEWzw4MFRrndjbDQ\"}";
//
//        Base64URL expected = Base64URL.encode(MessageDigest.getInstance("SHA-256").digest(orderedJSON.getBytes(StandardCharset.UTF_8)));
//
//        assertEquals(expected, thumbprint);
//    }


    public void testThumbprintSHA1()
            throws Exception {

        MLDSAKey mldsaKey = new MLDSAKey.Builder(ExampleKeyMLDSA44.ALG, ExampleKeyMLDSA44.pub).build();

        Base64URL thumbprint = mldsaKey.computeThumbprint("SHA-1");

        assertEquals(160 / 8, thumbprint.decode().length);
    }


    public void testThumbprintAsKeyID()
            throws Exception {

        MLDSAKey mldsaKey = new MLDSAKey.Builder(ExampleKeyMLDSA44.ALG, ExampleKeyMLDSA44.pub)
                .keyIDFromThumbprint()
                .build();

        Base64URL thumbprint = new Base64URL(mldsaKey.getKeyID());

        assertEquals(256 / 8, thumbprint.decode().length);

        String orderedJSON = JSONObjectUtils.toJSONString(mldsaKey.getRequiredParams());

        Base64URL expected = Base64URL.encode(MessageDigest.getInstance("SHA-256").digest(orderedJSON.getBytes(StandardCharset.UTF_8)));

        assertEquals(expected, thumbprint);
    }


    public void testThumbprintSHA1AsKeyID()
            throws Exception {

        MLDSAKey mldsaKey = new MLDSAKey.Builder(ExampleKeyMLDSA44.ALG, ExampleKeyMLDSA44.pub)
                .keyIDFromThumbprint("SHA-1")
                .build();

        Base64URL thumbprint = new Base64URL(mldsaKey.getKeyID());

        assertEquals(160 / 8, thumbprint.decode().length);
    }


    // See https://mailarchive.ietf.org/arch/msg/jose/gS-nOfqgV1n17DFUd6w_yBEf0sU
    public void testJose4jVectorP256()
            throws Exception {

        String json = "{\"kty\":\"AKP\"," +
                "\"alg\":\"ML-DSA-44\"," +
                "\"pub\":\"unH59k4RuutY-pxvu24U5h8YZD2rSVtHU5qRZsoBmBMcRPgmu9VuNOVdteXi1zNIXjnqJg_GAAxepLqA00Vc3lO0bzRIKu39VFD8Lhuk8l0V-cFEJC-zm7UihxiQMMUEmOFxe3x1ixkKZ0jqmqP3rKryx8tSbtcXyfea64QhT6XNje2SoMP6FViBDxLHBQo2dwjRls0k5a-XSQSu2OTOiHLoaWsLe8pQ5FLNfTDqmkrawDEdZyxr3oSWJAsHQxRjcIiVzZuvwxYy1zl2STiP2vy_fTBaPemkleynQzqPg7oPCyXEE8bjnJbrfWkbNNN8438e6tHPIX4l7zTuzz98YPhLjt_d6EBdT4MldsYe-Y4KLyjaGHcAlTkk9oa5RhRwW89T0z_t1DSO3dvfKLUGXh8gd1BD6Fz5MfgpF5NjoafnQEqDjsAAhrCXY4b-Y3yYJEdX4_dp3dRGdHG_rWcPmgX4JG7lCnser4f8QGnDriqiAzJYEXeS8LzUngg_0bx0lqv_KcyU5IaLISFO0xZSU5mmEPvdSoDnyAcV8pV44qhLtAvd29n0ehG259oRihtljTWeiu9V60a1N2tbZVl5mEqSK-6_xZvNYA1TCdzNctvweH24unV7U3wer9XA9Q6kvJWDVJ4oKaQsKMrCSMlteBJMRxWbGK7ddUq6F7GdQw-3j2M-qdJvVKm9UPjY9rc1lPgol25-oJxTu7nxGlbJUH-4m5pevAN6NyZ6lfhbjWTKlxkrEKZvQXs_Yf6cpXEwpI_ZJeriq1UC1XHIpRkDwdOY9MH3an4RdDl2r9vGl_IwlKPNdh_5aF3jLgn7PCit1FNJAwC8fIncAXgAlgcXIpRXdfJk4bBiO89GGccSyDh2EgXYdpG3XvNgGWy7npuSoNTE7WIyblAk13UQuO4sdCbMIuriCdyfE73mvwj15xgb07RZRQtFGlFTmnFcIdZ90zDrWXDbANntv7KCKwNvoTuv64bY3HiGbj-NQ-U9eMylWVpvr4hrXcES8c9K3PqHWADZC0iIOvlzFv4VBoc_wVflcOrL_SIoaNFCNBAZZq-2v5lAgpJTqVOtqJ_HVraoSfcKy5g45p-qULunXj6Jwq21fobQiKubBKKOZwcJFyJD7F4ACKXOrz-HIvSHMCWW_9dVrRuCpJw0s0aVFbRqopDNhu446nqb4_EDYQM1tTHMozPd_jKxRRD0sH75X8ZoToxFSpLBDbtdWcenxj-zBf6IGWfZnmaetjKEBYJWC7QDQx1A91pJVJCEgieCkoIfTqkeQuePpIyu48g2FG3P1zjRF-kumhUTfSjo5qS0YiZQy0E1BMs6M11EvuxXRsHClLHoy5nLYI2Sj4zjVjYyxSHyPRPGGo9hwB34yWxzYNtPPGiqXS_dNCpi_zRZwRY4lCGrQ-hYTEWIK1Dm5OlttvC4_eiQ1dv63NiGkLRJ5kJA3bICN0fzCDY-MBqnd1cWn8YVBijVkgtaoascjL9EywDgJdeHnXK0eeOvUxHHhXJVkNqcibn8O4RQdpVU60TSA-uiu675ytIjcBHC6kTv8A8pmkj_4oypPd-F92YIJC741swkYQoeIHj8rE-ThcMUkF7KqC5VORbZTRp8HsZSqgiJcIPaouuxd1-8Rxrid3fXkE6p8bkrysPYoxWEJgh7ZFsRCPDWX-yTeJwFN0PKFP1j0F6YtlLfK5wv-c4F8ZQHA_-yc_gODicy7KmWDZgbTP07e7gEWzw4MFRrndjbDQ\"" +
                "}";

        MLDSAKey mldsaKey = MLDSAKey.parse(json);

        assertEquals("T4xl70S7MT6Zeq6r9V9fPJGVn76wfnXJ21-gyo0Gu6o", mldsaKey.computeThumbprint().toString());
    }


    // See https://mailarchive.ietf.org/arch/msg/jose/gS-nOfqgV1n17DFUd6w_yBEf0sU
//    public void testJose4jVectorP384()
//            throws Exception {
//
//        String json = "{\"kty\":\"EC\"," +
//                " \"x\":\"2jCG5DmKUql9YPn7F2C-0ljWEbj8O8-vn5Ih1k7Wzb-y3NpBLiG1BiRa392b1kcQ\"," +
//                " \"y\":\"7Ragi9rT-5tSzaMbJlH_EIJl6rNFfj4V4RyFM5U2z4j1hesX5JXa8dWOsE-5wPIl\"," +
//                " \"crv\":\"P-384\"}";
//
//        ECKey ecKey = ECKey.parse(json);
//
//        assertEquals("vZtaWIw-zw95JNzzURg1YB7mWNLlm44YZDZzhrPNetM", ecKey.computeThumbprint().toString());
//    }


    // See https://mailarchive.ietf.org/arch/msg/jose/gS-nOfqgV1n17DFUd6w_yBEf0sU
//    public void testJose4jVectorP521()
//            throws Exception {
//
//        String json = "{\"kty\":\"EC\"," +
//                "\"x\":\"Aeq3uMrb3iCQEt0PzSeZMmrmYhsKP5DM1oMP6LQzTFQY9-F3Ab45xiK4AJxltXEI-87g3gRwId88hTyHgq180JDt\"," +
//                "\"y\":\"ARA0lIlrZMEzaXyXE4hjEkc50y_JON3qL7HSae9VuWpOv_2kit8p3pyJBiRb468_U5ztLT7FvDvtimyS42trhDTu\"," +
//                "\"crv\":\"P-521\"}";
//
//        ECKey ecKey = ECKey.parse(json);
//
//        assertEquals("rz4Ohmpxg-UOWIWqWKHlOe0bHSjNUFlHW5vwG_M7qYg", ecKey.computeThumbprint().toString());
//    }


    // For private EC keys as PKCS#11 handle
//    public void testPrivateKeyHandle()
//            throws Exception {
//
//        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
//        gen.initialize(Curve.P_256.toECParameterSpec());
//        final KeyPair kp = gen.generateKeyPair();
//
//        ECPublicKey publicKey = (ECPublicKey) kp.getPublic();
//        PrivateKey privateKey = new PrivateKey() {
//            // simulate private PKCS#11 key with inaccessible key material
//            @Override
//            public String getAlgorithm() {
//                return kp.getPrivate().getAlgorithm();
//            }
//
//
//            @Override
//            public String getFormat() {
//                return kp.getPrivate().getFormat();
//            }
//
//
//            @Override
//            public byte[] getEncoded() {
//                return new byte[0];
//            }
//        };
//
//        ECKey ecJWK = new ECKey.Builder(Curve.P_256, publicKey)
//                .privateKey(privateKey)
//                .keyID("1")
//                .build();
//
//        assertNotNull(ecJWK.toPublicKey());
//        assertEquals(privateKey, ecJWK.toPrivateKey());
//        assertTrue(ecJWK.isPrivate());
//
//        KeyPair kpOut = ecJWK.toKeyPair();
//        assertNotNull(kpOut.getPublic());
//        assertEquals(privateKey, kpOut.getPrivate());
//
//        Map<String, Object> json = ecJWK.toJSONObject();
//        assertEquals("EC", json.get(JWKParameterNames.KEY_TYPE));
//        assertEquals("1", json.get(JWKParameterNames.KEY_ID));
//        assertEquals("P-256", json.get(JWKParameterNames.ELLIPTIC_CURVE));
//        assertNotNull(json.get(JWKParameterNames.ELLIPTIC_CURVE_X_COORDINATE));
//        assertNotNull(json.get(JWKParameterNames.ELLIPTIC_CURVE_Y_COORDINATE));
//        assertEquals(5, json.size());
//    }


//    public void testX509CertificateChain()
//            throws Exception {
//
//        List<X509Certificate> chain = X509CertChainUtils.parse(SampleCertificates.SAMPLE_X5C_EC);
//
//        ECPublicKey ecPublicKey = (ECPublicKey) chain.get(0).getPublicKey();
//
//        ECKey jwk = new ECKey.Builder(Curve.P_256, ecPublicKey)
//                .x509CertChain(SampleCertificates.SAMPLE_X5C_EC)
//                .build();
//
//        assertEquals(SampleCertificates.SAMPLE_X5C_EC.get(0), jwk.getX509CertChain().get(0));
//
//        String json = jwk.toJSONString();
//
//        jwk = ECKey.parse(json);
//
//        assertEquals(SampleCertificates.SAMPLE_X5C_EC.get(0), jwk.getX509CertChain().get(0));
//    }


//    public void testX509CertificateChain_algDoesNotMatch() {
//        try {
//            new ECKey.Builder(
//                    ExampleKeyP256.CRV,
//                    ExampleKeyP256.X,
//                    ExampleKeyP256.Y
//            )
//                    .x509CertChain(SampleCertificates.SAMPLE_X5C_RSA)
//                    .build();
//        } catch (IllegalStateException e) {
//            assertEquals("The public subject key info of the first X.509 certificate in the chain must match the JWK type and public parameters", e.getMessage());
//        }
//    }


//    public void testX509CertificateChain_xAndYdoNotMatch()
//            throws Exception {
//
//        List<X509Certificate> chain = X509CertChainUtils.parse(SampleCertificates.SAMPLE_X5C_EC);
//
//        ECPublicKey ecPublicKey = (ECPublicKey) chain.get(0).getPublicKey();
//
//        ECKey jwk = new ECKey.Builder(Curve.P_256, ecPublicKey)
//                .build();
//
//        try {
//            new ECKey.Builder(Curve.P_256, ExampleKeyP256.X, ExampleKeyP256.Y)
//                    .x509CertChain(SampleCertificates.SAMPLE_X5C_EC)
//                    .build();
//        } catch (IllegalStateException e) {
//            assertEquals("The public subject key info of the first X.509 certificate in the chain must match the JWK type and public parameters", e.getMessage());
//        }
//    }


//    public void testParseFromX509Cert()
//            throws Exception {
//
//        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
//        String pemEncodedCert = IOUtils.readFileToString(new File("src/test/resources/sample-certs/wikipedia.crt"), StandardCharset.UTF_8);
//        X509Certificate cert = X509CertUtils.parse(pemEncodedCert);
//        ECKey ecKey = ECKey.parse(cert);
//
//        assertEquals(KeyType.EC, ecKey.getKeyType());
//        assertEquals(Curve.P_256, ecKey.getCurve());
//        assertNull(ecKey.getKeyUse());
//        assertEquals(cert.getSerialNumber().toString(10), ecKey.getKeyID());
//        assertEquals(1, ecKey.getX509CertChain().size());
//        assertNull(ecKey.getX509CertThumbprint());
//        assertEquals(Base64URL.encode(sha256.digest(cert.getEncoded())), ecKey.getX509CertSHA256Thumbprint());
//        assertNull(ecKey.getAlgorithm());
//        assertNull(ecKey.getKeyOperations());
//        assertEquals(1511337599L, DateUtils.toSecondsSinceEpoch(ecKey.getExpirationTime()));
//        assertEquals(1479715200L, DateUtils.toSecondsSinceEpoch(ecKey.getNotBeforeTime()));
//        assertNull(ecKey.getIssueTime());
//        assertNull(ecKey.getKeyRevocation());
//    }


//    public void testParseFromX509CertWithRSAPublicKey()
//            throws Exception {
//
//        String pemEncodedCert = IOUtils.readFileToString(new File("src/test/resources/sample-certs/ietf.crt"), StandardCharset.UTF_8);
//        X509Certificate cert = X509CertUtils.parse(pemEncodedCert);
//
//        try {
//            ECKey.parse(cert);
//            fail();
//        } catch (JOSEException e) {
//            assertEquals("The public key of the X.509 certificate is not EC", e.getMessage());
//        }
//    }


//    public void testLoadFromKeyStore()
//            throws Exception {
//
//        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
//
//        char[] password = "secret".toCharArray();
//        keyStore.load(null, password);
//
//        // Generate key pair
//        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
//        gen.initialize(Curve.P_521.toECParameterSpec());
//        KeyPair kp = gen.generateKeyPair();
//        ECPublicKey publicKey = (ECPublicKey)kp.getPublic();
//        ECPrivateKey privateKey = (ECPrivateKey)kp.getPrivate();
//
//        // Generate certificate
//        X500Name issuer = new X500Name("cn=c2id");
//        BigInteger serialNumber = new BigInteger(64, new SecureRandom());
//        Date now = new Date();
//        Date nbf = new Date(now.getTime() - 1000L);
//        Date exp = new Date(now.getTime() + 365*24*60*60*1000L); // in 1 year
//        X500Name subject = new X500Name("cn=c2id");
//        JcaX509v3CertificateBuilder x509certBuilder = new JcaX509v3CertificateBuilder(
//                issuer,
//                serialNumber,
//                nbf,
//                exp,
//                subject,
//                publicKey
//        );
//        KeyUsage keyUsage = new KeyUsage(KeyUsage.nonRepudiation);
//        x509certBuilder.addExtension(Extension.keyUsage, true, keyUsage);
//        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withECDSA");
//        X509CertificateHolder certHolder = x509certBuilder.build(signerBuilder.build(privateKey));
//        X509Certificate cert = X509CertUtils.parse(certHolder.getEncoded());
//
//        // Store
//        keyStore.setKeyEntry("1", privateKey, "1234".toCharArray(), new java.security.cert.Certificate[]{cert});
//
//        // Load
//        ECKey ecKey = ECKey.load(keyStore, "1", "1234".toCharArray());
//        assertNotNull(ecKey);
//        assertEquals(Curve.P_521, ecKey.getCurve());
//        assertEquals(KeyUse.SIGNATURE, ecKey.getKeyUse());
//        assertEquals("1", ecKey.getKeyID());
//        assertEquals(1, ecKey.getX509CertChain().size());
//        assertNull(ecKey.getX509CertThumbprint());
//        assertNotNull(ecKey.getX509CertSHA256Thumbprint());
//        assertEquals(DateUtils.toSecondsSinceEpoch(exp), DateUtils.toSecondsSinceEpoch(ecKey.getExpirationTime()));
//        assertEquals(DateUtils.toSecondsSinceEpoch(nbf), DateUtils.toSecondsSinceEpoch(ecKey.getNotBeforeTime()));
//        assertNull(ecKey.getIssueTime());
//        assertNull(ecKey.getKeyRevocation());
//        assertTrue(ecKey.isPrivate());
//        assertEquals(keyStore, ecKey.getKeyStore());
//
//        // Try to load with bad pin
//        try {
//            ECKey.load(keyStore, "1", "".toCharArray());
//            fail();
//        } catch (JOSEException e) {
//            assertTrue(e.getMessage().startsWith("Couldn't retrieve private EC key (bad pin?): "));
//            assertTrue(e.getCause() instanceof UnrecoverableKeyException);
//        }
//    }


//    public void testLoadFromKeyStore_publicKeyOnly()
//            throws Exception {
//
//        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
//
//        char[] password = "secret".toCharArray();
//        keyStore.load(null, password);
//
//        String pemEncodedCert = IOUtils.readFileToString(new File("src/test/resources/sample-certs/wikipedia.crt"), StandardCharset.UTF_8);
//        X509Certificate cert = X509CertUtils.parse(pemEncodedCert);
//
//        keyStore.setCertificateEntry("1", cert);
//
//        ECKey ecKey = ECKey.load(keyStore, "1", null);
//        assertNotNull(ecKey);
//        assertEquals(Curve.P_256, ecKey.getCurve());
//        assertNull(ecKey.getKeyUse());
//        assertEquals("1", ecKey.getKeyID());
//        assertEquals(1, ecKey.getX509CertChain().size());
//        assertNull(ecKey.getX509CertThumbprint());
//        assertNotNull(ecKey.getX509CertSHA256Thumbprint());
//        assertFalse(ecKey.isPrivate());
//        assertEquals(keyStore, ecKey.getKeyStore());
//    }


//    public void testLoadFromKeyStore_notEC()
//            throws Exception {
//
//        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
//
//        char[] password = "secret".toCharArray();
//        keyStore.load(null, password);
//
//        String pemEncodedCert = IOUtils.readFileToString(new File("src/test/resources/sample-certs/ietf.crt"), StandardCharset.UTF_8);
//        X509Certificate cert = X509CertUtils.parse(pemEncodedCert);
//
//        keyStore.setCertificateEntry("1", cert);
//
//        try {
//            ECKey.load(keyStore, "1", null);
//            fail();
//        } catch (JOSEException e) {
//            assertEquals("Couldn't load EC JWK: The key algorithm is not EC", e.getMessage());
//        }
//    }


//    public void testLoadFromKeyStore_notFound()
//            throws Exception {
//
//        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
//
//        char[] password = "secret".toCharArray();
//        keyStore.load(null, password);
//
//        assertNull(ECKey.load(keyStore, "1", null));
//    }


    // iss #217
//    public void testEnsurePublicXYCoordinatesOnCurve() {
//
//        try {
//            new ECKey(
//                    Curve.P_256,
//                    ExampleKeyP384Alt.X, // on diff curve
//                    ExampleKeyP384Alt.Y, // on diff curve
//                    null,
//                    null,
//                    null,
//                    null,
//                    null,
//                    null,
//                    null,
//                    null,
//                    null);
//            fail();
//        } catch (IllegalArgumentException e) {
//            assertEquals("Invalid EC JWK: The 'x' and 'y' public coordinates are not on the P-256 curve", e.getMessage());
//        }
//
//        try {
//            new ECKey(
//                    Curve.P_256,
//                    ExampleKeyP384Alt.X, // on diff curve
//                    ExampleKeyP384Alt.Y, // on diff curve
//                    ExampleKeyP256.D,    // private D coordinate
//                    null,
//                    null,
//                    null,
//                    null,
//                    null,
//                    null,
//                    null,
//                    null,
//                    null);
//            fail();
//        } catch (IllegalArgumentException e) {
//            assertEquals("Invalid EC JWK: The 'x' and 'y' public coordinates are not on the P-256 curve", e.getMessage());
//        }
//    }


    // iss #217
//    public void testCurveMismatch()
//            throws Exception {
//
//        // EC key on P_256
//        ECParameterSpec ecParameterSpec = Curve.P_256.toECParameterSpec();
//        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
//        generator.initialize(ecParameterSpec);
//        KeyPair keyPair = generator.generateKeyPair();
//        ECKey ecJWK_p256 = new ECKey.Builder(Curve.P_256, (ECPublicKey) keyPair.getPublic())
//                .privateKey((ECPrivateKey) keyPair.getPrivate())
//                .build();
//
//        // EC key on P_384
//        ecParameterSpec = Curve.P_384.toECParameterSpec();
//        generator = KeyPairGenerator.getInstance("EC");
//        generator.initialize(ecParameterSpec);
//        keyPair = generator.generateKeyPair();
//        ECKey ecJWK_p384 = new ECKey.Builder(Curve.P_384, (ECPublicKey) keyPair.getPublic())
//                .privateKey((ECPrivateKey) keyPair.getPrivate())
//                .build();
//
//
//        // Try to create EC key with P_256 params, but with x and y from P_384 curve key
//
//        ECPoint w = new ECPoint(ecJWK_p384.getX().decodeToBigInteger(), ecJWK_p384.getY().decodeToBigInteger());
//        ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(w, Curve.P_256.toECParameterSpec());
//
//        // Default Sun provider
//        try {
//            KeyFactory keyFactory = KeyFactory.getInstance("EC");
//            keyFactory.generatePublic(publicKeySpec);
//            fail();
//        } catch (RuntimeException e) {
//            assertEquals("Point coordinates do not match field size", e.getMessage());
//        }
//
//        // BouncyCastle provider
//        try {
//            KeyFactory keyFactory = KeyFactory.getInstance("EC", BouncyCastleProviderSingleton.getInstance());
//            keyFactory.generatePublic(publicKeySpec);
//            fail();
//        } catch (InvalidKeySpecException e) {
//            assertEquals("invalid KeySpec: x value invalid for SecP256R1FieldElement", e.getMessage());
//        }
//    }

//    public void testEqualsSuccess()
//            throws Exception {
//
//        //Given
//        String jsonA = "{\n" +
//                "    \"kty\" : \"EC\",\n" +
//                "    \"crv\" : \"P-256\",\n" +
//                "    \"x\"   : \"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\n" +
//                "    \"y\"   : \"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\n" +
//                "    \"use\" : \"enc\",\n" +
//                "    \"kid\" : \"1\"\n" +
//                "  }";
//        ECKey ecKeyA = ECKey.parse(jsonA.replaceAll("\n", ""));
//        ECKey ecKeyB = ECKey.parse(jsonA.replaceAll("\n", ""));
//
//        //When
//
//        //Then
//        assertEquals(ecKeyA, ecKeyB);
//    }

//    public void testEqualsFailure()
//            throws Exception {
//
//        //Given
//        String jsonA = "{\n" +
//                "    \"kty\" : \"EC\",\n" +
//                "    \"crv\" : \"P-256\",\n" +
//                "    \"x\"   : \"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\n" +
//                "    \"y\"   : \"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\n" +
//                "    \"use\" : \"enc\",\n" +
//                "    \"kid\" : \"1\"\n" +
//                "  }";
//        ECKey ecKeyA = ECKey.parse(jsonA.replaceAll("\n", ""));
//
//        String jsonB = "{\n" +
//                "      \"kty\": \"EC\",\n" +
//                "      \"d\": \"l3zQlaKsoql3cBEQzVpFnWIyHyGRh_C3cc0l3iqnljE\",\n" +
//                "      \"crv\": \"P-256\",\n" +
//                "      \"x\": \"LE9B4rxnp-1kzJsDBM-UYTsewGooMgt1Pi_czT_E7SI\",\n" +
//                "      \"y\": \"fs_LRmTZVHRUZintk-BLOpIjOjxTmVXF9ddrwNuRH9U\",\n" +
//                "      \"use\" : \"enc\",\n" +
//                "      \"kid\" : \"1\"\n" +
//                "    }";
//        ECKey ecKeyB = ECKey.parse(jsonB.replaceAll("\n", ""));
//
//        //When
//
//        //Then
//        assertNotEquals(ecKeyA, ecKeyB);
//    }


//    public void testParse_fromEmptyJSONObject() {
//
//        try {
//            ECKey.parse(JSONObjectUtils.newJSONObject());
//            fail();
//        } catch (ParseException e) {
//            assertEquals("The key type to parse must not be null", e.getMessage());
//        }
//    }


//    public void testParse_missingCurve() {
//
//        Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
//        jsonObject.put(JWKParameterNames.KEY_TYPE, "EC");
//        jsonObject.put(JWKParameterNames.ELLIPTIC_CURVE_X_COORDINATE, "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4");
//        jsonObject.put(JWKParameterNames.ELLIPTIC_CURVE_Y_COORDINATE, "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM");
//        try {
//            ECKey.parse(jsonObject);
//            fail();
//        } catch (ParseException e) {
//            assertEquals("The cryptographic curve string must not be null or empty", e.getMessage());
//        }
//    }


//    public void testParse_missingX() {
//
//        Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
//        jsonObject.put(JWKParameterNames.KEY_TYPE, "EC");
//        jsonObject.put(JWKParameterNames.ELLIPTIC_CURVE, "P-256");
//        jsonObject.put(JWKParameterNames.ELLIPTIC_CURVE_Y_COORDINATE, "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM");
//        try {
//            ECKey.parse(jsonObject);
//            fail();
//        } catch (ParseException e) {
//            assertEquals("The x coordinate must not be null", e.getMessage());
//        }
//    }


//    public void testParse_missingY() {
//
//        Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
//        jsonObject.put(JWKParameterNames.KEY_TYPE, "EC");
//        jsonObject.put(JWKParameterNames.ELLIPTIC_CURVE, "P-256");
//        jsonObject.put(JWKParameterNames.ELLIPTIC_CURVE_X_COORDINATE, "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4");
//        try {
//            ECKey.parse(jsonObject);
//            fail();
//        } catch (ParseException e) {
//            assertEquals("The y coordinate must not be null", e.getMessage());
//        }
//    }


//    public void testToRevokedJWK() throws JOSEException {
//
//        ECKey jwk = new ECKeyGenerator(Curve.P_256).generate();
//
//        jwk = jwk.toRevokedJWK(KEY_REVOCATION);
//
//        assertEquals(KEY_REVOCATION, jwk.getKeyRevocation());
//    }


//    public void testToRevokedJWK_fullySpecced() throws Exception {
//
//        URI x5u = new URI("http://example.com/jwk.json");
//        Base64URL x5t = new Base64URL("abc");
//        List<Base64> x5c = null;
//
//        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
//
//        ECKey jwk = new ECKey.Builder(Curve.P_256, ExampleKeyP256.X, ExampleKeyP256.Y)
//                .d(ExampleKeyP256.D)
//                .keyUse(KeyUse.SIGNATURE)
//                .algorithm(JWSAlgorithm.ES256)
//                .keyID("1")
//                .x509CertURL(x5u)
//                .x509CertThumbprint(x5t)
//                .x509CertChain(x5c)
//                .expirationTime(EXP)
//                .notBeforeTime(NBF)
//                .issueTime(IAT)
//                .keyStore(keyStore)
//                .build();
//
//        jwk = jwk.toRevokedJWK(KEY_REVOCATION);
//
//        // Test getters
//        assertEquals(KeyUse.SIGNATURE, jwk.getKeyUse());
//        assertEquals(JWSAlgorithm.ES256, jwk.getAlgorithm());
//        assertEquals("1", jwk.getKeyID());
//        assertEquals(x5u.toString(), jwk.getX509CertURL().toString());
//        assertEquals(x5t.toString(), jwk.getX509CertThumbprint().toString());
//        assertNull(jwk.getX509CertChain());
//        assertNull(jwk.getParsedX509CertChain());
//        assertEquals(EXP, jwk.getExpirationTime());
//        assertEquals(NBF, jwk.getNotBeforeTime());
//        assertEquals(IAT, jwk.getIssueTime());
//        assertEquals(KEY_REVOCATION, jwk.getKeyRevocation());
//        assertEquals(keyStore, jwk.getKeyStore());
//
//        assertEquals(Curve.P_256, jwk.getCurve());
//        assertEquals(ExampleKeyP256.X, jwk.getX());
//        assertEquals(ExampleKeyP256.Y, jwk.getY());
//        assertEquals(ExampleKeyP256.D, jwk.getD());
//
//        assertTrue(jwk.isPrivate());
//    }


//    public void testToRevokedJWK_alreadyRevoked() throws JOSEException {
//
//        ECKey jwk = new ECKeyGenerator(Curve.P_256).generate();
//
//        jwk = new ECKey.Builder(jwk)
//                .keyRevocation(KEY_REVOCATION)
//                .build();
//
//        assertEquals(KEY_REVOCATION, jwk.getKeyRevocation());
//
//        try {
//            jwk.toRevokedJWK(KEY_REVOCATION);
//            fail();
//        } catch (IllegalStateException e) {
//            assertEquals("Already revoked", e.getMessage());
//        }
//    }


//    public void testToRevokedJWK_nullKeyRevocation() throws JOSEException {
//
//        ECKey jwk = new ECKeyGenerator(Curve.P_256).generate();
//
//        try {
//            jwk.toRevokedJWK(null);
//            fail();
//        } catch (NullPointerException e) {
//            assertNull(e.getMessage());
//        }
//    }
}
