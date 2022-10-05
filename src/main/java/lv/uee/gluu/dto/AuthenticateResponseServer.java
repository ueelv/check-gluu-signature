package lv.uee.gluu.dto;

import java.io.Serializable;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import lv.uee.gluu.exception.BadInputException;

public class AuthenticateResponseServer implements Serializable {

    private static final long serialVersionUID = -4854326288654670000L;

    /**
     * base64(UTF8(client data))
     */
    @JsonProperty
    private final String clientData;

    @JsonIgnore
    private transient ClientData clientDataRef;

    /* base64(raw response from U2F device) */
    @JsonProperty
    private final String signatureData;

    /* keyHandle originally passed */
    @JsonProperty
    private final String keyHandle;

    public AuthenticateResponseServer(@JsonProperty("clientData") String clientData, @JsonProperty("signatureData") String signatureData,
                                      @JsonProperty("keyHandle") String keyHandle) throws BadInputException {
        this.clientData = clientData;
        this.signatureData = signatureData;
        this.keyHandle = keyHandle;
        this.clientDataRef = new ClientData(clientData);
    }

    public ClientData getClientData() {
        return clientDataRef;
    }

    public String getClientDataRaw() {
        return clientData;
    }

    public String getSignatureData() {
        return signatureData;
    }

    public String getKeyHandle() {
        return keyHandle;
    }

    @JsonIgnore
    public String getRequestId() {
        return getClientData().getChallenge();
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("AuthenticateResponse [clientData=").append(clientData).append(", signatureData=").append(signatureData).append(", keyHandle=")
                .append(keyHandle).append("]");
        return builder.toString();
    }

}
