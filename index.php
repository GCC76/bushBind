<?php

//Exemple of use

include_once("bushBind.php");

$testo = "
Con il termine lorem ipsum si indica un testo segnaposto utilizzato da grafici, progettisti, programmatori e tipografi a modo riempitivo per bozzetti e prove grafiche.[1] È un testo privo di senso, composto da parole (o parti di parole) in lingua latina, riprese pseudocasualmente dal De finibus bonorum et malorum scritto da Cicerone del 45 a.C, a volte alterate con l'inserzione di passaggi ironici. La caratteristica principale è data dal fatto che offre una distribuzione delle lettere uniforme, apparendo come un normale blocco di testo leggibile.

Il testo fu utilizzato per la prima volta nel 1500 da un anonimo tipografo per mostrare i propri caratteri; da allora è diventato lo standard dell'industria tipografica. È sopravvissuto non solo a più di cinque secoli, ma anche al passaggio alla videoimpaginazione, pervenendoci sostanzialmente inalterato. Fu reso popolare, negli anni '60, con la diffusione dei fogli di caratteri trasferibili, detti anche trasferelli, e successivamente dai programmi di grafica. La sua funzione lo avvicina al testo ETAOIN SHRDLU un tempo usato per provare le Linotype.[2]

In informatica è usato molto frequentemente come testo riempitivo nelle prove grafiche di pagine web e come dati fittizi nella prova di funzionamento dei database. L'uso di questo espediente, per riempire spazi altrimenti vuoti (spesso in attesa dei dati definitivi), è molto efficace grazie soprattutto all'alternanza di parole lunghe e brevi, punteggiatura e paragrafi. In questo modo viene simulato con sufficiente verosimiglianza l'impatto grafico di un testo reale, in modo particolare per quanto riguarda l'impatto estetico.

Questa consuetudine come testo segnaposto standard ha fatto sì che la maggior parte dei software di grafica e tipografia adottassero funzioni e strumenti di \"riempimento automatico\", con un'immediata anteprima dello spazio occupato e della resa finale.[3][4][5]
<br><br>

«Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque laudantium, totam rem aperiam eaque ipsa, quae ab illo inventore veritatis et quasi architecto beatae vitae dicta sunt, explicabo. Nemo enim ipsam voluptatem, quia voluptas sit, aspernatur aut odit aut fugit, sed quia consequuntur magni dolores eos, qui ratione voluptatem sequi nesciunt, neque porro quisquam est, qui dolorem ipsum, quia dolor sit, amet, consectetur, adipisci velit, sed quia non numquam eius modi tempora incidunt, ut labore et dolore magnam aliquam quaerat voluptatem. Ut enim ad minima veniam, quis nostrum exercitationem ullam corporis suscipit laboriosam, nisi ut aliquid ex ea commodi consequatur? Quis autem vel eum iure reprehenderit, qui in ea voluptate velit esse, quam nihil molestiae consequatur, vel illum, qui dolorem eum fugiat, quo voluptas nulla pariatur? [33] At vero eos et accusamus et iusto odio dignissimos ducimus, qui blanditiis praesentium voluptatum deleniti atque corrupti, quos dolores et quas molestias excepturi sint, obcaecati cupiditate non provident, similique sunt in culpa, qui officia deserunt mollitia animi, id est laborum et dolorum fuga. Et harum quidem rerum facilis est et expedita distinctio. Nam libero tempore, cum soluta nobis est eligendi optio, cumque nihil impedit, quo minus id, quod maxime placeat, facere possimus, omnis voluptas assumenda est, omnis dolor repellendus. Temporibus autem quibusdam et aut officiis debitis aut rerum necessitatibus saepe eveniet, ut et voluptates repudiandae sint et molestiae non recusandae. Itaque earum rerum hic tenetur a sapiente delectus, ut aut reiciendis voluptatibus maiores alias consequatur aut perferendis doloribus asperiores repellat.»
<br><br>

«Tuttavia, perché voi intendiate da dove sia nato tutto questo errore, di quelli che incolpano il piacere ed esaltano il dolore, io spiegherò tutta la questione, e presenterò le idee espresse dal famoso esploratore della verità, vorrei quasi dire dal costruttore della felicità umana. Nessuno, infatti, detesta, odia, o rifugge il piacere in quanto tale, solo perché è piacere, ma perché grandi sofferenze colpiscono quelli che non sono capaci di raggiungere il piacere attraverso la ragione; e al contrario, non c'è nessuno che ami, insegua, voglia raggiungere il dolore in sé stesso, soltanto perché è dolore, ma perché qualche volta accadono situazioni tali per cui attraverso la sofferenza o il dolore si cerca di raggiungere un qualche grande piacere. Concentrandoci su casi di piccola importanza: chi di noi intraprende un esercizio ginnico faticoso, se non per ottenerne un qualche vantaggio? E d'altra parte, chi avrebbe motivo di criticare, colui che desidera provare un piacere, cui non segua nessun fastidio, o colui che fugge un dolore che non produce nessun piacere?
[33] Al contrario, però, noi con indignazione denunciamo e riteniamo meritevoli di odio quelli che, rammolliti e corrotti dai piaceri del momento, a quali dolori e a quali sofferenze andranno incontro, accecati dal desiderio non prevedono, e uguale colpa hanno quelli che abbandonano i propri doveri per pigrizia d'animo, cioè per evitare i dolori e le fatiche. Certamente è facile e rapido distinguere questi casi. Infatti nel tempo libero, quando abbiamo tutta la nostra possibilità di scegliere e niente ci ostacola dal fare ciò che ci piace di più, bisogna accogliere ogni piacere e respingere ogni dolore. Ma in altri momenti, o nei doveri inevitabili o negli obblighi che ci vengono dalle circostanze, spesso accadrà che si debba respingere il piacere e accogliere il fastidio. E così il saggio si regola scegliendo tra questi atteggiamenti, facendo in modo che o – respingendo il piacere – ne ottenga di più grandi, o – sopportando il dolore – ne eviti di peggiori.»

";

$password="StrongPassword_required12";


$code = new bushBind();

//Start encryption
$coded = $code->bushEncrypt($testo,$password);
$response = json_decode($coded,true);

if($response['response']['value'] == true){
	
	$token	= $response['response']['security_token'];
	$data 	= $response['response']['data'];
	
} else {
	
	die($response['response']['data']);

}

//Start decryption
$encoded = $code->bushDecrypt($data,$password,$token);
$response = json_decode($encoded,true);
if($response['response']['value'] == true){
	$data = base64_decode($response['response']['data']);
} else {
	
	die($response['response']['data']);

}

echo $data;

?>