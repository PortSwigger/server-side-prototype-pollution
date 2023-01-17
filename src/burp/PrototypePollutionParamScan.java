package burp;

import com.google.gson.JsonElement;

import java.util.List;
import java.util.Map;

public class PrototypePollutionParamScan extends ParamScan {

    public PrototypePollutionParamScan(String name) {
        super(name);
    }

    @Override
    List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        Utilities.out("--Running param scan--");
        injectInsertionPoint(baseRequestResponse, insertionPoint, PrototypePollutionBodyScan.jsonTechniques);
        return null;
    }

    public void injectInsertionPoint(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint, Map<String, String[]> techniques) {
        IHttpService service = baseRequestResponse.getHttpService();
        for (Map.Entry<String, String[]> technique : techniques.entrySet()) {
            if(!PrototypePollutionBodyScan.shouldUseTechnique(technique)) {
                continue;
            }
            String attackType = technique.getKey();
            String attackInjection = technique.getValue()[1];
            String nullifyInjection = technique.getValue()[2];
            String baseValue = insertionPoint.getBaseValue();
            byte[] attackReq;

            if (insertionPoint.getInsertionPointType() != IScannerInsertionPoint.INS_PARAM_JSON) {
                baseValue = PrototypePollutionBodyScan.urlDecodeWithoutPlus(baseValue).trim();
            }

            if (insertionPoint.getInsertionPointType() == IScannerInsertionPoint.INS_PARAM_JSON) {
                attackReq = insertionPoint.buildRequest(attackInjection.getBytes());
            } else if (baseValue.trim().startsWith("{") && PrototypePollutionBodyScan.isValidJson(baseValue)) {
                attackReq = baseRequestResponse.getRequest().clone();
                JsonElement attackJson = PrototypePollutionBodyScan.generateJson(baseValue, technique.getValue(), false);
                attackReq = Utilities.helpers.updateParameter(attackReq, PrototypePollutionBodyScan.createParameter(insertionPoint.getInsertionPointName(), attackJson.toString(), insertionPoint.getInsertionPointType()));
            } else {
                continue;
            }

            Resp attackResp = request(service, attackReq, PrototypePollutionBodyScan.MAX_RETRIES);

            if (attackResp.failed()) {
                continue;
            }

            Utilities.out("Doing param scan " + attackType + " attack");
            if (attackType.contains("reflection")) {
                byte[] req;
                if (baseValue.equals("{}")) {
                    req = baseRequestResponse.getRequest().clone();
                    req = Utilities.helpers.updateParameter(req, PrototypePollutionBodyScan.createParameter(insertionPoint.getInsertionPointName(), "{\"test\":\"test\"}", insertionPoint.getInsertionPointType()));
                } else {
                    req = baseRequestResponse.getRequest();
                }

                Resp baseResp = request(service, req, PrototypePollutionBodyScan.MAX_RETRIES);
                if (baseResp.getReq().getResponse() == null) {
                    continue;
                }
                String response = Utilities.getBody(baseResp.getReq().getResponse());
                String attackResponseStr = Utilities.getBody(attackResp.getReq().getResponse());

                if (PrototypePollutionBodyScan.responseHas(response, PrototypePollutionBodyScan.REFLECTION_CANARY)) {
                    PrototypePollutionBodyScan.reportIssue("Potential Server side prototype pollution via object reflection", "Potential " + PrototypePollutionBodyScan.DETAIL + " Using the technique "+attackType+".", "Medium", "Firm", PrototypePollutionBodyScan.REMEDIATION, baseRequestResponse.getRequest(), attackResp, baseResp);
                } else if (!PrototypePollutionBodyScan.responseHas(attackResponseStr, PrototypePollutionBodyScan.REFLECTION_CANARY)) {
                    byte[] nullifyAttackRequest;
                    if (insertionPoint.getInsertionPointType() == IScannerInsertionPoint.INS_PARAM_JSON) {
                        nullifyAttackRequest = insertionPoint.buildRequest(nullifyInjection.getBytes());
                    } else {
                        byte[] baseReq = baseRequestResponse.getRequest().clone();
                        JsonElement attackJson = PrototypePollutionBodyScan.generateJson(baseValue, technique.getValue(), true);
                        nullifyAttackRequest = Utilities.helpers.updateParameter(baseReq, PrototypePollutionBodyScan.createParameter(insertionPoint.getInsertionPointName(), attackJson.toString(), insertionPoint.getInsertionPointType()));
                    }
                    request(service, nullifyAttackRequest, PrototypePollutionBodyScan.MAX_RETRIES);
                    Resp nullifyResponse = request(service, baseRequestResponse.getRequest(), PrototypePollutionBodyScan.MAX_RETRIES);

                    if (nullifyResponse.getReq().getResponse() == null || nullifyResponse.failed()) {
                        continue;
                    }

                    String nullifyResponseStr = Utilities.getBody(nullifyResponse.getReq().getResponse());
                    if (PrototypePollutionBodyScan.responseHas(nullifyResponseStr, PrototypePollutionBodyScan.REFLECTION_CANARY)) {
                        PrototypePollutionBodyScan.reportIssue("Potential Server side prototype pollution via object reflection", "Potential " + PrototypePollutionBodyScan.DETAIL + " Using the technique", "Medium", "Firm", PrototypePollutionBodyScan.REMEDIATION, baseRequestResponse.getRequest(), attackResp, baseResp);
                    }
                }
            } else if(attackType.contains("non reflected property")) {
                String attackResponse = Utilities.getBody(attackResp.getReq().getResponse());
                if (PrototypePollutionBodyScan.responseHas(attackResponse, PrototypePollutionBodyScan.REFLECTION_PROPERTY_NAME) && !PrototypePollutionBodyScan.responseHas(attackResponse, PrototypePollutionBodyScan.REFLECTION_VIA_PROTO_PROPERTY_NAME)) {
                    PrototypePollutionBodyScan.reportIssue("Server side prototype pollution via JSON non reflected property", "Potential " + PrototypePollutionBodyScan.DETAIL + " Using the technique", "Medium", "Firm", PrototypePollutionBodyScan.REMEDIATION, baseRequestResponse.getRequest(), attackResp);
                }
            } else if(attackType.contains("blitz")) {
                byte[] req = baseRequestResponse.getRequest();
                Resp baseResp = request(service, req, PrototypePollutionBodyScan.MAX_RETRIES);

                if(attackResp.getReq().getResponse() == null) {
                    continue;
                }

                String response = Utilities.getBody(attackResp.getReq().getResponse());
                Boolean hasCorrectResponse = PrototypePollutionBodyScan.responseHas(response, PrototypePollutionBodyScan.BLITZ_REGEX);
                Boolean hasStatusCode500 = PrototypePollutionBodyScan.hasStatusCode(500, attackResp);
                if(hasCorrectResponse || hasStatusCode500) {
                    byte[] nullifyAttackRequest;
                    if(insertionPoint.getInsertionPointType() == IScannerInsertionPoint.INS_PARAM_JSON) {
                        nullifyAttackRequest = insertionPoint.buildRequest(nullifyInjection.getBytes());
                    } else {
                        byte[] baseReq = baseRequestResponse.getRequest().clone();
                        JsonElement attackJson = PrototypePollutionBodyScan.generateJson(baseValue, technique.getValue(), true);
                        nullifyAttackRequest = Utilities.helpers.updateParameter(baseReq, PrototypePollutionBodyScan.createParameter(insertionPoint.getInsertionPointName(), attackJson.toString(),insertionPoint.getInsertionPointType()));
                    }
                    request(service, nullifyAttackRequest, PrototypePollutionBodyScan.MAX_RETRIES);
                    Resp nullifyResponse = request(service, baseRequestResponse.getRequest(), PrototypePollutionBodyScan.MAX_RETRIES);

                    if(nullifyResponse.failed() || nullifyResponse.getReq().getResponse() == null) {
                        continue;
                    }

                    String nullifyResponseStr = Utilities.getBody(nullifyResponse.getReq().getResponse());
                    if((hasCorrectResponse && !PrototypePollutionBodyScan.responseHas(nullifyResponseStr, PrototypePollutionBodyScan.BLITZ_REGEX)) || (hasStatusCode500 && !PrototypePollutionBodyScan.hasStatusCode(500, nullifyResponse))) {
                        PrototypePollutionBodyScan.reportIssue("Server side prototype pollution via JSON Blitz", PrototypePollutionBodyScan.DETAIL + " Using the technique", "High", "Firm", PrototypePollutionBodyScan.REMEDIATION, baseRequestResponse.getRequest(), attackResp, baseResp, nullifyResponse);
                    }
                }
            } else if(attackType.contains("spacing")) {
                byte[] req;
                if(baseValue.equals("{}")) {
                    req = baseRequestResponse.getRequest().clone();
                    req = Utilities.helpers.updateParameter(req, PrototypePollutionBodyScan.createParameter(insertionPoint.getInsertionPointName(), "{\"test\":\"test\"}", insertionPoint.getInsertionPointType()));
                } else {
                    req = baseRequestResponse.getRequest();
                }

                Resp baseResp = request(service, req, PrototypePollutionBodyScan.MAX_RETRIES);
                if(baseResp.getReq().getResponse() == null) {
                    continue;
                }
                String response = Utilities.getBody(baseResp.getReq().getResponse());
                if(PrototypePollutionBodyScan.hasSpacing(response)) {
                    byte[] nullifyAttackRequest;
                    if(insertionPoint.getInsertionPointType() == IScannerInsertionPoint.INS_PARAM_JSON) {
                        nullifyAttackRequest = insertionPoint.buildRequest(nullifyInjection.getBytes());
                    } else {
                        byte[] baseReq = baseRequestResponse.getRequest().clone();
                        JsonElement attackJson = PrototypePollutionBodyScan.generateJson(baseValue, technique.getValue(), true);
                        nullifyAttackRequest = Utilities.helpers.updateParameter(baseReq, PrototypePollutionBodyScan.createParameter(insertionPoint.getInsertionPointName(), attackJson.toString(),insertionPoint.getInsertionPointType()));
                    }
                    request(service, nullifyAttackRequest, PrototypePollutionBodyScan.MAX_RETRIES);
                    Resp nullifyResponse = request(service, baseRequestResponse.getRequest(), PrototypePollutionBodyScan.MAX_RETRIES);

                    if(nullifyResponse.getReq().getResponse() == null || nullifyResponse.failed()) {
                        continue;
                    }

                    String nullifyResponseStr = Utilities.getBody(nullifyResponse.getReq().getResponse());
                    if(!PrototypePollutionBodyScan.hasSpacing(nullifyResponseStr)) {
                        PrototypePollutionBodyScan.reportIssue("Server side prototype pollution via JSON spacing", PrototypePollutionBodyScan.DETAIL + " Using the technique", "High", "Firm", PrototypePollutionBodyScan.REMEDIATION, baseRequestResponse.getRequest(), attackResp, baseResp, nullifyResponse);
                    }
                }
            } else if(attackType.contains("status")) {
                Resp invalidJsonResp = makeInvalidJsonRequest(service, insertionPoint);
                String response = Utilities.getBody(invalidJsonResp.getReq().getResponse());
                Boolean has510Status = PrototypePollutionBodyScan.hasStatusCode(510, invalidJsonResp);
                Boolean has510StatusInJson = PrototypePollutionBodyScan.responseHas(response, "\"statusCode\":510");
                if(has510Status || has510StatusInJson) {
                    byte[] nullifyAttackRequest;
                    if(insertionPoint.getInsertionPointType() == IScannerInsertionPoint.INS_PARAM_JSON) {
                        nullifyAttackRequest = insertionPoint.buildRequest(nullifyInjection.getBytes());
                    } else {
                        byte[] baseReq = baseRequestResponse.getRequest().clone();
                        JsonElement attackJson = PrototypePollutionBodyScan.generateJson(baseValue, technique.getValue(), true);
                        nullifyAttackRequest = Utilities.helpers.updateParameter(baseReq, PrototypePollutionBodyScan.createParameter(insertionPoint.getInsertionPointName(), attackJson.toString(),insertionPoint.getInsertionPointType()));
                    }
                    Resp nullifyAttackRequestResp = request(service, nullifyAttackRequest, PrototypePollutionBodyScan.MAX_RETRIES);

                    if(nullifyAttackRequestResp.failed()) {
                        continue;
                    }

                    Resp invalidJsonNullified = makeInvalidJsonRequest(service, insertionPoint);
                    String nullifiedResponse = Utilities.getBody(invalidJsonNullified.getReq().getResponse());
                    if((has510Status && !PrototypePollutionBodyScan.hasStatusCode(510, invalidJsonNullified)) || (has510StatusInJson && !PrototypePollutionBodyScan.responseHas(nullifiedResponse, "\"statusCode\":510"))) {
                        PrototypePollutionBodyScan.reportIssue("Server side prototype pollution via JSON status", PrototypePollutionBodyScan.DETAIL + " Using the technique", "High", "Firm", PrototypePollutionBodyScan.REMEDIATION, baseRequestResponse.getRequest(), attackResp, invalidJsonResp, nullifyAttackRequestResp, invalidJsonNullified);
                    }
                }
            } else if(attackType.contains("options")) {
                Resp optionsResp = request(service, Utilities.setMethod(baseRequestResponse.getRequest(), "OPTIONS"), PrototypePollutionBodyScan.MAX_RETRIES);

                if(optionsResp.failed() || optionsResp.getReq().getResponse() == null) {
                    continue;
                }

                String allow = Utilities.getHeader(optionsResp.getReq().getResponse(), "Allow").toLowerCase();
                if(!allow.contains("head") && allow.length() > 0) {
                    byte[] nullifyAttackRequest;
                    if(insertionPoint.getInsertionPointType() == IScannerInsertionPoint.INS_PARAM_JSON) {
                        nullifyAttackRequest = insertionPoint.buildRequest(nullifyInjection.getBytes());
                    } else {
                        byte[] baseReq = baseRequestResponse.getRequest().clone();
                        JsonElement attackJson = PrototypePollutionBodyScan.generateJson(baseValue, technique.getValue(), true);
                        nullifyAttackRequest = Utilities.helpers.updateParameter(baseReq, PrototypePollutionBodyScan.createParameter(insertionPoint.getInsertionPointName(), attackJson.toString(),insertionPoint.getInsertionPointType()));
                    }
                    request(service, nullifyAttackRequest, PrototypePollutionBodyScan.MAX_RETRIES);
                    Resp nullifyAttackRequestResp = request(service, nullifyAttackRequest, PrototypePollutionBodyScan.MAX_RETRIES);

                    if(nullifyAttackRequestResp.failed()) {
                        continue;
                    }

                    Resp nullifyOptionsResp = request(service, Utilities.setMethod(baseRequestResponse.getRequest(), "OPTIONS"), PrototypePollutionBodyScan.MAX_RETRIES);

                    if(nullifyOptionsResp.failed() || nullifyOptionsResp.getReq().getResponse() == null) {
                        continue;
                    }

                    String nullifiedAllow = Utilities.getHeader(nullifyOptionsResp.getReq().getResponse(), "Allow").toLowerCase();
                    if(nullifiedAllow.contains("head")) {
                        PrototypePollutionBodyScan.reportIssue("Server side prototype pollution via JSON options", PrototypePollutionBodyScan.DETAIL + " Using the technique", "High", "Firm", PrototypePollutionBodyScan.REMEDIATION, baseRequestResponse.getRequest(), attackResp, optionsResp, nullifyAttackRequestResp, nullifyOptionsResp);
                    }
                }
            } else if(attackType.contains("exposedHeaders")) {
                Resp baseResp = request(service, baseRequestResponse.getRequest(), PrototypePollutionBodyScan.MAX_RETRIES);

                if(baseResp.failed()) {
                    continue;
                }

                String accessControlExposeHeaders = Utilities.getHeader(baseResp.getReq().getResponse(), "Access-Control-Expose-Headers").toLowerCase();
                if(accessControlExposeHeaders.contains(PrototypePollutionBodyScan.CANARY)) {
                    byte[] nullifyAttackRequest;
                    if(insertionPoint.getInsertionPointType() == IScannerInsertionPoint.INS_PARAM_JSON) {
                        nullifyAttackRequest = insertionPoint.buildRequest(nullifyInjection.getBytes());
                    } else {
                        byte[] baseReq = baseRequestResponse.getRequest().clone();
                        JsonElement attackJson = PrototypePollutionBodyScan.generateJson(baseValue, technique.getValue(), true);
                        nullifyAttackRequest = Utilities.helpers.updateParameter(baseReq, PrototypePollutionBodyScan.createParameter(insertionPoint.getInsertionPointName(), attackJson.toString(),insertionPoint.getInsertionPointType()));
                    }
                    request(service, nullifyAttackRequest, PrototypePollutionBodyScan.MAX_RETRIES);
                    Resp nullifyAttackRequestResp = request(service, nullifyAttackRequest, PrototypePollutionBodyScan.MAX_RETRIES);

                    if(nullifyAttackRequestResp.failed()) {
                        continue;
                    }

                    Resp nullifyResp = request(service, baseRequestResponse.getRequest(), PrototypePollutionBodyScan.MAX_RETRIES);

                    if(nullifyResp.failed() || nullifyResp.getReq().getResponse() == null) {
                        continue;
                    }

                    String nullifiedAccessControlExposeHeaders = Utilities.getHeader(nullifyResp.getReq().getResponse(), "Access-Control-Expose-Headers").toLowerCase();
                    if(!nullifiedAccessControlExposeHeaders.contains(PrototypePollutionBodyScan.CANARY)) {
                        PrototypePollutionBodyScan.reportIssue("Server side prototype pollution via JSON exposedHeaders", PrototypePollutionBodyScan.DETAIL + " Using the technique", "High", "Firm", PrototypePollutionBodyScan.REMEDIATION, baseRequestResponse.getRequest(), attackResp, baseResp, nullifyAttackRequestResp, nullifyAttackRequestResp, nullifyResp);
                    }
                }
            }
        }
    }

    private Resp makeInvalidJsonRequest(IHttpService service, IScannerInsertionPoint insertionPoint) {
        String invalidJson = "{";
        byte[] invalidJsonAttackRequest;
        if(insertionPoint.getInsertionPointType() == IScannerInsertionPoint.INS_PARAM_JSON) {
            invalidJsonAttackRequest = insertionPoint.buildRequest(invalidJson.getBytes());
        } else {
            invalidJsonAttackRequest = insertionPoint.buildRequest(PrototypePollutionBodyScan.urlEncodeWithoutPlus(invalidJson).getBytes());
        }
        return request(service, invalidJsonAttackRequest, PrototypePollutionBodyScan.MAX_RETRIES);
    }
}
