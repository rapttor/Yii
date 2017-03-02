<?php

/*

// This is datasource.php

<?php
// Allow access from anywhere. Can be domains or * (any)
header('Access-Control-Allow-Origin: *');

// Allow these methods of data retrieval
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');

// Allow these header types
header('Access-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept');

// Create our data object in that crazy unique PHP way
$arr = array(array("artist" => 1, "artistName" => "AC/DC", "genre" => "Rock", "image" => "acdc.jpg", "description" => "AC/DC are an Australian hard rock band, formed in 1973 by brothers Malcolm and Angus Young. To date they are one of the highest-grossing bands of all time."));

// Return as JSON
echo json_encode($arr);
?>


# with AJAX withCredentials=false (cookies NOT sent)
Header always set Access-Control-Allow-Origin "*"
Header always set Access-Control-Allow-Methods "POST, GET, PUT, OPTIONS, PATCH, DELETE"
Header always set Access-Control-Allow-Headers "X-Accept-Charset,X-Accept,Content-Type"
RewriteEngine On
RewriteCond %{REQUEST_METHOD} OPTIONS
RewriteRule ^(.*)$ $1 [R=200,L,E=HTTP_ORIGIN:%{HTTP:ORIGIN}]]

# with AJAX withCredentials=true (cookies sent, SSL allowed...)
SetEnvIfNoCase ORIGIN (.*) ORIGIN=$1
Header always set Access-Control-Allow-Methods "POST, GET, PUT, OPTIONS, PATCH, DELETE"
Header always set Access-Control-Allow-Origin "%{ORIGIN}"
Header always set Access-Control-Allow-Credentials "true"
Header always set Access-Control-Allow-Headers "X-Accept-Charset,X-Accept,Content-Type"
RewriteEngine On
RewriteCond %{REQUEST_METHOD} OPTIONS
RewriteRule ^(.*)$ $1 [R=200,L,E=HTTP_ORIGIN:%{HTTP:ORIGIN}]

*/


class ApiController extends Controller
{
    // Members
    /**
     * Key which has to be in HTTP USERNAME and PASSWORD headers
     */
    Const APPLICATION_ID = 'RAPTTORRESTAPI';

    /**
     * Default response format
     * either 'json' or 'xml'
     */
    private $format = 'json';

    // common parameters
    private $model = null;
    private $id = null;
    private $data = null;
    private $class = null;
    private $post = null;
    private $limit = 10;

    /**
     * @return array action filters
     */
    public function filters()
    {
        return array();
    }

    public function actionError() {
        if ($error = Yii::app()->errorHandler->error) {
            $this->_sendResponse(403,$error);
        } else $this->_sendResponse(400,"General error");
    }

    public function init()
    {
        parent::init();
        Yii::app()->errorHandler->errorAction='/api/error';

        if (isset($_SERVER['HTTP_ORIGIN'])) {
            header("Access-Control-Allow-Origin: {$_SERVER['HTTP_ORIGIN']}");
            header('Access-Control-Allow-Credentials: true');
            header('Access-Control-Max-Age: 86400');    // cache for 1 day
        }
// Access-Control headers are received during OPTIONS requests
        if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {

            if (isset($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_METHOD']))
                header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");

            if (isset($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS']))
                header("Access-Control-Allow-Headers: {$_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS']}");

        }

        $this->model = Yii::app()->request->getQuery("model", null);
        $this->class = ucfirst($this->model);
        $this->id = Yii::app()->request->getQuery("id", null);
        $this->data = null;
        $this->post = (isset($_POST)) ? $_POST : null;
        defined("CACHETIME") or define("CACHETIME", 60);
    }

    public function error($message, $errorcode = 400)
    {
        $this->_sendResponse($errorcode, $message);
        // auto end app.
    }

    public function mapFields($row, $api = null)
    {
        $a = array();
        if (!is_null($api)) {
            if ($api) foreach ($api as $k => $i) {
                $f = (is_array($i) && isset($i["field"])) ? $i["field"] : $i;
                if (isset($row[$f]))
                    $a[$k] = $row[$f];
            }
        } else $a = $row;
        return $a;
    }

    public function restFields($class=null)
    {
        if (is_null($class)) $class = $this->class;
        return (method_exists($class, "restFields")) ? $class::restFields() : null;
    }

    public function restList($class=null)
    {
        if (is_null($class)) $class = $this->class;
        return (method_exists($class, "restList")) ? $class::restList() : null;
    }

    // Actions
    public function actionIndex($limit = null, $page = null)
    {
        $model = $this->model;
        if (!$model || is_null($model)) {
            $this->_sendResponse(403, json_encode(array("error" => "Forbidden")));
        }
        $data = $this->data;
        $class = $this->class;
        $limit = (is_null($limit)) ? $this->limit : $limit;
        $page = (is_null($page)) ? 0 : $page;

        // Get the respective model instance
        if (!is_null($model)) switch ($model) {
            default:
                if (@class_exists($class)) {
                    $criteria = new CDbCriteria();
                    $criteria->limit = $limit;
                    $criteria->offset = $page * $limit;
                    try {

                        $data = $class::model()->cache(CACHETIME)->findAll($criteria);
                    } catch (Exception $e) {
                        $this->error("Cannot find records in $model");
                    }
                } else $this->error("Cannot find model: $model");
        } else $this->error("No model defined");
        // Did we get some results?
        if (empty($data)) {
            // No
            $this->_sendResponse(200,
                sprintf('No items where found for model <b>%s</b>', $model));
        } else {
            // Prepare response
            $rows = array();
            $api = (!is_null($this->restList())) ? $this->restList() : $this->restFields();
            foreach ($data as $row)
                $rows[] = $this->mapFields($row, $api);
            // Send the response
            $this->_sendResponse(200, CJSON::encode($rows));
        }
    }

    public function actionRest()
    {
        //die("test");
        $class = $this->class;
        if (class_exists($class)) {
            $c = new $class();
            $info = array();
            if (method_exists($class, "attributeLabels"))
                $info["post"] = $c->attributeLabels();
            if (method_exists($class, "restFields"))
                $info["fields"] = $c->restFields();
            if (method_exists($class, "restList"))
                $info["list"] = $c->restList();


            $info["config"] = array(
                "limit" => array("value" => $this->limit, "description" => "items per page"),
            );
            $this->_sendResponse(200, json_encode($info));
        } else $this->_sendResponse(403, "No info");

    }

    public function actionSchema()
    {
        $info = array();


        if (!is_null($this->model)) {
            $class = $this->class;
            $c = new $class();
            $info[$this->model] = $c->getMetaData();
        } else {
            $models = glob('./protected/models/*.php');
            foreach ($models as $k => $i) $models[$k] = str_ireplace(array('./protected/models/', '.php'), '', $i);
            $info["models"] = $models;
        }
        $this->_sendResponse(200, json_encode($info));
    }

    public function actionView()
    {
        $model = $this->model;
        $id = $this->id;
        $class = $this->class;
        
        // Check if id was submitted via GET
        if (!isset($id))
            $this->_sendResponse(500, 'Error: Parameter <b>id</b> is missing');

        switch ($model) {
            // Find respective model
            default:
                $data = $class::model()->cache(CACHETIME)->findByPk($id);
                if (!$data) {
                    $this->_sendResponse(501, sprintf(
                        'Mode <b>view</b> is not implemented for model <b>%s</b>',
                        $model));
                    Yii::app()->end();
                } else {
                    $api = $this->restFields();
                    $data = $this->mapFields($data, $api);
                }
        }
        // Did we find the requested model? If not, raise an error
        if (is_null($data))
            $this->_sendResponse(404, 'No Item found with id ' . $id);
        else
            $this->_sendResponse(200, CJSON::encode($data));
    }

    public function actionCreate()
    {
        $model = $this->model;
        $data = $this->data;
        $class = $this->class;
        if (class_exists($class)) switch ($model) {
            // Get an instance of the respective model
            default:
                $data = new $class;
        }
        // Try to assign POST values to attributes
        foreach ($_POST as $var => $value) {
            // Does the model have this attribute? If not raise an error
            if ($data->hasAttribute($var))
                $data->$var = $value;
            else
                $this->_sendResponse(500,
                    sprintf('Parameter <b>%s</b> is not allowed for model <b>%s</b>', $var,
                        $_GET['model']));
        }
        // Try to save the model
        if ($data->save())
            $this->_sendResponse(200, CJSON::encode($data));
        else {
            // Errors occurred
            $msg = "<h1>Error</h1>";
            $msg .= sprintf("Couldn't create model <b>%s</b>", $model);
            $msg .= "<ul>";
            foreach ($data->errors as $attribute => $attr_errors) {
                $msg .= "<li>Attribute: $attribute</li>";
                $msg .= "<ul>";
                foreach ($attr_errors as $attr_error)
                    $msg .= "<li>$attr_error</li>";
                $msg .= "</ul>";
            }
            $msg .= "</ul>";
            $this->_sendResponse(500, $msg);
        }
    }

    public function actionUpdate()
    {
        $model = $this->model;
        $id = $this->id;
        $data = $this->data;
        $class = $this->class;
        $json = $this->post;
        // Parse the PUT parameters. This didn't work: parse_str(file_get_contents('php://input'), $put_vars);
        $put_vars = CJSON::decode($json, true);  //true means use associative array

        if (!is_null($model) && !is_null($id)) switch ($model) {
            // Find respective model
            default:
                $data = $class::model()->findByPk($id);
        }
        // Did we find the requested model? If not, raise an error
        if ($data === null)
            $this->_sendResponse(400,
                sprintf("Error: Didn't find any model <b>%s</b> with ID <b>%s</b>.",
                    $model, $id));

        // Try to assign PUT parameters to attributes
        foreach ($put_vars as $var => $value) {
            // Does model have this attribute? If not, raise an error
            if ($data->hasAttribute($var))
                $data->$var = $value;
            else {
                $this->_sendResponse(500,
                    sprintf('Parameter <b>%s</b> is not allowed for model <b>%s</b>',
                        $var, $model));
            }
        }
        // Try to save the model
        if ($data->save())
            $this->_sendResponse(200, CJSON::encode($data));
        else
            $msg = "Cannot update record $id in $model";
        $this->_sendResponse(500, $msg);
    }

    public function actionDelete()
    {

        $model = $this->model;
        $id = $this->id;
        $class = $this->class;

        $this->_checkAuth();

        if (!is_null($model) && !is_null($id)) switch ($model) {
            // Load the respective model
            case 'X': // special case
                break;
            default:
                $data = $class::model()->findByPk($id);
        }
        // Was a model found? If not, raise an error
        if (is_null($data))
            $this->_sendResponse(400,
                sprintf("Error: Didn't find any model <b>%s</b> with ID <b>%s</b>.",
                    $model, $id));

        // Delete the model
        $num = $data->delete();
        if ($num > 0)
            $this->_sendResponse(200, $num);    //this is the only way to work with backbone
        else
            $this->_sendResponse(500,
                sprintf("Error: Couldn't delete model <b>%s</b> with ID <b>%s</b>.",
                    $model, $id));
    }

    private function _sendResponse($status = 200, $body = '', $content_type = 'text/html')
    {
        // set the status
        $status_header = 'HTTP/1.1 ' . $status . ' ' . $this->_getStatusCodeMessage($status);
        header($status_header);
        // and the content type
        header('Content-type: ' . $content_type);

        // pages with body are easy
        if (is_array($body)) { // array2json
            echo json_encode($body);
        } else  if ($body != '') {
            // send the body
            echo $body;
        } // we need to create the body if none is passed
        else {
            // create some body messages
            $message = '';

            // this is purely optional, but makes the pages a little nicer to read
            // for your users.  Since you won't likely send a lot of different status codes,
            // this also shouldn't be too ponderous to maintain
            switch ($status) {
                case 401:
                    $message = 'You must be authorized to view this page.';
                    break;
                case 404:
                    $message = 'The requested URL ' . $_SERVER['REQUEST_URI'] . ' was not found.';
                    break;
                case 500:
                    $message = 'The server encountered an error processing your request.';
                    break;
                case 501:
                    $message = 'The requested method is not implemented.';
                    break;
            }

            // servers don't always have a signature turned on
            // (this is an apache directive "ServerSignature On")
            $signature = ($_SERVER['SERVER_SIGNATURE'] == '') ? $_SERVER['SERVER_SOFTWARE'] . ' Server at ' . $_SERVER['SERVER_NAME'] . ' Port ' . $_SERVER['SERVER_PORT'] : $_SERVER['SERVER_SIGNATURE'];

            // this should be templated in a real-world solution
            $body = '
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html>
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">
    <title>' . $status . ' ' . $this->_getStatusCodeMessage($status) . '</title>
</head>
<body>
    <h1>' . $this->_getStatusCodeMessage($status) . '</h1>
    <p>' . $message . '</p>
    <hr />
    <address>' . $signature . '</address>
</body>
</html>';

            echo $body;
        }
        Yii::app()->end();
    }


    private function _getStatusCodeMessage($status)
    {
        // these could be stored in a .ini file and loaded
        // via parse_ini_file()... however, this will suffice
        // for an example
        $codes = Array(
            200 => 'OK',
            400 => 'Bad Request',
            401 => 'Unauthorized',
            402 => 'Payment Required',
            403 => 'Forbidden',
            404 => 'Not Found',
            500 => 'Internal Server Error',
            501 => 'Not Implemented',
        );
        return (isset($codes[$status])) ? $codes[$status] : '';
    }

    

    private function _checkAuth()
    {
        //var_dump($_SERVER);
        // Check if we have the USERNAME and PASSWORD HTTP headers set?
        if (isset($_SERVER['HTTP_X_BEARER'])) {
            $bearer = $_SERVER['HTTP_X_BEARER'];
            $user = Profile::model()->findByAttributes(array('bearer'=>$bearer));
            //$user["bearer"]=$bearer;
            //echo $bearer;
            //var_dump($user->attributes); die;
        } else { 
            if (!(isset($_SERVER['HTTP_X_USERNAME']) and isset($_SERVER['HTTP_X_PASSWORD']))) {
                // Error: Unauthorized
                $this->_sendResponse(401, array("error"=>"Unauthorized"));
            }
            $username = $_SERVER['HTTP_X_USERNAME']; // email
            $password = $_SERVER['HTTP_X_PASSWORD'];
            $user = Profile::model()->find('LOWER(email)=?', array(strtolower($username)));
        
            // Find the user
            if ($user === null) {
                // Error: Unauthorized
                $this->_sendResponse(401, array("error"=>"User Name is invalid"));
            } else if (!$user->validatePassword($password)) {
                // Error: Unauthorized
                $this->_sendResponse(401, array("error"=>'User Password is invalid'));
            } else {
                $model = new LoginForm;
                $model->username=$username;
                $model->password=$password;
                if (($model->validate() && $model->login())) {
                    $user->bearer=$this->generateBearer();
                    //$user->bearer_expire=date("m-d-Y", strtotime("+1 week"));
                    if (!$user->save()) $user=null;
                } else {
                    $user=null;
                }
            }
        }
        if ($user) unset($user->password);
        return ($user)?$user->attributes:$user;
    }

    public function generateBearer() {
        return $this->generate_uuid().'-'.sha1(base64_encode(uniqid()));
    }

    private function generate_uuid() {
    return sprintf( '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
        // 32 bits for "time_low"
        mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff ),
        // 16 bits for "time_mid"
        mt_rand( 0, 0xffff ),
        // 16 bits for "time_hi_and_version",
        // four most significant bits holds version number 4
        mt_rand( 0, 0x0fff ) | 0x4000,
        // 16 bits, 8 bits for "clk_seq_hi_res",
        // 8 bits for "clk_seq_low",
        // two most significant bits holds zero and one for variant DCE1.1
        mt_rand( 0, 0x3fff ) | 0x8000,
        // 48 bits for "node"
        mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff )
    );
}

    public function checkAuth() {
        return $this->_checkAuth();
    }

    public function actionAction($action=null, $id=0) {
        $auth=$this->_checkAuth();
        //echo $this->class.'/'.$this->model." / ".$action.' ['.$id.']';
        if ($auth && method_exists($this->class, $action) && is_callable(array($this->class, $action))) {
            $class=new $this->class;
            $params=$_GET;
            var_dump($params); die;
            $result=call_user_func_array(array($class, $action), $params);
            //$result=array("result"=>$result,"auth"=>$auth);
            $this->_sendResponse(is_array($result)?200:400, $result);
            //die("Exists");            
            Yii::app()->end();
            //die;
        }
        //echo $this->model." / ".$action.' ['.$id.']';
    }

}