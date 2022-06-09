package burp;
import java.util.List;

public class FatGet extends ParamScan {

    FatGet(String name) {
        super(name);
    }

    @Override
    List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        // don't scan POST
        if (baseRequestResponse.getRequest()[0] == 'P') {
            return null;
        }

        // set value to canary
        String canary = Utilities.generateCanary();

        String fullValue = insertionPoint.getBaseValue()+canary;
        byte[] poison = insertionPoint.buildRequest(fullValue.getBytes());

        // convert to POST
        poison = Utilities.helpers.toggleRequestMethod(poison);

        poison = Utilities.fixContentLength(Utilities.replaceFirst(poison, canary.getBytes(), (canary).getBytes()));

        // convert method back to GET
        poison = Utilities.setMethod(poison, "GET");

        poison = Utilities.addOrReplaceHeader(poison, "X-HTTP-Method-Override", "POST");
        poison = Utilities.addOrReplaceHeader(poison, "X-HTTP-Method", "POST");
        poison = Utilities.addOrReplaceHeader(poison, "X-Method-Override", "POST");

        poison = Utilities.addCacheBuster(poison, Utilities.generateCanary());

        IHttpService service = baseRequestResponse.getHttpService();

        Resp resp = request(service, poison);
        byte[] response = resp.getReq().getResponse();

        if (Utilities.containsBytes(response, canary.getBytes())) {

            recordCandidateFound();

            // report("Fat-GET body reflection", canary, resp);
            for (int i=0; i<5; i++) {
                request(service, poison);
            }

            //String toReplace = insertionPoint.getInsertionPointName()+"="+fullValue;
            String toReplace = canary;

            byte[] getPoison = Utilities.fixContentLength(Utilities.replaceFirst(poison, toReplace.getBytes(), "".getBytes()));
//            byte[] getPoison = baseRequestResponse.getRequest();
//            getPoison = Utilities.appendToQuery(getPoison, "x="+cacheBuster);


            Resp poisonedResp = request(service, getPoison);
            if (Utilities.containsBytes(poisonedResp.getReq().getResponse(), canary.getBytes())) {
                report("Web Cache Poisoning via Fat GET", "The application lets users pass parameters in the body of GET requests, but does not include them in the cache key. This was confirmed by injecting the value "+canary+" using the "+insertionPoint.getInsertionPointName()+" parameter, then replaying the request without the injected value, and confirming it still appears in the response.<br><br>For further information on this technique, please refer to https://portswigger.net/research/web-cache-entanglement", resp, poisonedResp);
            }
        }

        return null;
    }

    @Override
    List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
        return null;
    }

}
