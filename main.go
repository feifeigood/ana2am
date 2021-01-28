package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/levigross/grequests"
	"github.com/prometheus/alertmanager/template"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// build information
var (
	VERSION   string
	BUILDDATE string
)

// Alerting represents ana alerting table.
type Alerting struct {
	ID           int        `gorm:"column:id"`
	Type         int        `gorm:"column:fm_type"`
	RuleID       int        `gorm:"column:fm_ruleid"`
	Code         string     `gorm:"column:fm_itemcode"`
	THigh        float64    `gorm:"column:fm_thresholdhigh"`
	TLow         float64    `gorm:"column:fm_thresholdlow"`
	Unit         string     `gorm:"column:fm_unit"`
	Value        float64    `gorm:"column:fm_alarmvalue"`
	StartsAt     *time.Time `gorm:"column:fm_begintime"`
	UpdateAt     *time.Time `gorm:"column:fm_latelytime"`
	Total        int        `gorm:"column:fm_alarmtimes"`
	Status       int        `gorm:"column:fm_alarmstatus"`
	CustomerID   int        `gorm:"column:fm_ciid"`
	CustomerName string     `gorm:"column:fm_ciname"`
	Extra        string     `gorm:"column:fm_extrainfo"`
}

// TableName returns database table name.
func (Alerting) TableName() string {
	return "fm_alarminfo"
}

// AlertingRule represnets ana alerting rule table.
type AlertingRule struct {
	DomainID     int     `gorm:"column:domain_id"`
	Domain       string  `gorm:"column:domain"`
	RuleID       int     `gorm:"column:rule_id"`
	RuleName     string  `gorm:"column:rule_name"`
	THigh        float32 `gorm:"column:threshold_high"`
	TLow         float32 `gorm:"column:threshold_low"`
	Unit         string  `gorm:"column:unit"`
	Attention    int     `gorm:"column:attention_threshold"`
	CustomerID   int     `gorm:"column:ci_id"`
	Email        string  `gorm:"column:notify_mail"`
	ResponseCode string  `gorm:"column:response_code"`
	DiffType     int     `gorm:"column:diff_type"`
}

var (
	printVersion = flag.Bool("version", false, "show program version")
	dsn          = flag.String("dsn", "root:123456@tcp(127.0.0.1:3306)/integration?charset=utf8mb4&parseTime=True&loc=Local", "set DSN(data-source-name) for connect DB")
	interval     = flag.Duration("interval", time.Duration(2*time.Minute), "interval for scan alerting")
	webhook      = flag.String("webhook", "", "set alertmanager webhook")

	err  error
	db   *gorm.DB
	term = make(chan os.Signal, 1)

	ALERTING_NAME_EN = map[string]string{
		"1002": "HTTP Code Sum Error(1002)",               // 状态码数量告警
		"1005": "HTTP Error Code High(1005)",              // 错误状态码告警
		"1007": "HTTP Code Percentage Error(1007)",        // 状态码占比告警
		"0302": "Edge Server Bandwidth Error(0302)",       // 带宽故障告警
		"0303": "Origin Server Bandwidth D2D Error(0303)", // 回源环比告警
		"0401": "Origin Server Bandwidth High(0401)",      // 普通回源告警
		"0701": "Request Hit Rate Error(0701)",            //命中率告警
	}
)

func main() {
	flag.Parse()
	if *printVersion {
		fmt.Printf("version: %s build_date: %s\n", VERSION, BUILDDATE)
		os.Exit(0)
	}

	if *dsn == "" {
		flag.Usage()
		os.Exit(1)
	}

	if db, err = gorm.Open(
		mysql.New(mysql.Config{DSN: *dsn}),
		&gorm.Config{DisableForeignKeyConstraintWhenMigrating: true, Logger: logger.Default.LogMode(logger.Silent)},
	); err != nil {
		log.Fatalf("%v\n", err)
	}

	ticker := time.NewTicker(*interval)
	fn := func() {

		alerts := getAlerting()
		if len(alerts) == 0 {
			return
		}

		rules := getAlertingRule()
		if rules == nil {
			return
		}
		rulemap := make(map[int]AlertingRule)
		for _, rule := range rules {
			rule := rule
			rulemap[rule.RuleID] = rule
		}

		as := []template.Alert{}
		for _, a := range alerts {
			if _, ok := rulemap[a.RuleID]; !ok {
				log.Printf("Missing rule id: %d, alerting: %v\n", a.RuleID, a)
				continue
			}

			if result := buildAlertmanagerMessage(rulemap[a.RuleID], a); result != nil {
				as = append(as, *result)
			}
		}

		if len(as) == 0 {
			return
		}

		byt, _ := json.Marshal(as)
		log.Println(string(byt))

		resp, err := grequests.Post(*webhook, &grequests.RequestOptions{JSON: as})
		if err != nil {
			log.Printf("Request err: %v\n", err)
			return
		}

		if resp.Ok != true {
			log.Println("Request did not return OK")
			return
		}

		log.Println("Request return OK")
	}

	go func() {
		fn()
		for range ticker.C {
			fn()
		}
	}()

	<-term
	log.Println("Received SIGTERM, exiting gracefully....")
}

func timeIn(t time.Time, name string) (time.Time, error) {
	loc, err := time.LoadLocation(name)
	if err == nil {
		t = t.In(loc)
	}

	return t, err
}

func buildAlertmanagerMessage(rule AlertingRule, alert Alerting) *template.Alert {
	startsAt, _ := timeIn(*alert.StartsAt, "Asia/Shanghai")
	result := &template.Alert{
		StartsAt: startsAt,
		Labels: template.KV{
			"alertname":     ALERTING_NAME_EN[alert.Code],
			"severity":      "critical",
			"rule_id":       alert.Code,
			"domain":        rule.Domain,
			"customer":      alert.CustomerName,
			"to_customer":   "yes",
			"zenlayer_aiop": "yes",
		},
		Annotations: template.KV{
			"description": "",
		},
	}

	if strings.Contains(rule.Email, "only_cdn_devops") {
		result.Labels["to_customer"] = "no"
	}

	if alert.Code == "1002" {
		result.Annotations["description"] = fmt.Sprintf("threshold: gt %.2f%s, VALUE: %.2f%s, http code: %s", rule.THigh, rule.Unit, alert.Value, alert.Unit, rule.ResponseCode)
	} else if alert.Code == "1005" || alert.Code == "1007" {
		// example: 1600706700:8.670:(6935/79986):410 499:410/6914 499/21
		extras := strings.Split(alert.Extra, ":")
		if len(extras) != 5 {
			log.Printf("Alerting ID: %d, fm_extrainfo column couldn't parse %s", alert.ID, alert.Extra)
			return nil
		}
		result.Annotations["description"] = fmt.Sprintf("threshold: gt %.2f%s, VALUE: %.2f%s, count: %s, detail: %s", rule.THigh, rule.Unit, alert.Value, alert.Unit, extras[2], extras[4])
	} else if alert.Code == "0302" {
		if rule.DiffType != 1 && rule.DiffType != 7 {
			log.Printf("Alerting ID: %d, Rule ID: %d, diff_type column not equal 1,7", alert.ID, rule.RuleID)
			return nil
		}
		// example: 1600755000:7.2886,1600150200:26158.3969
		extras := strings.Split(alert.Extra, ",")
		if len(extras) != 2 {
			log.Printf("Alerting ID: %d, fm_extrainfo column couldn't parse %s", alert.ID, alert.Extra)
			return nil
		}
		cpv1 := strings.Split(extras[0], ":")
		cpv2 := strings.Split(extras[1], ":")
		if len(cpv1) != 2 || len(cpv2) != 2 {
			log.Printf("Alerting ID: %d, fm_extrainfo column couldn't parse %s", alert.ID, alert.Extra)
			return nil
		}

		timestamp1, _ := strconv.ParseInt(cpv1[0], 10, 64)
		timestamp2, _ := strconv.ParseInt(cpv2[0], 10, 64)
		t1 := time.Unix(timestamp1, 0)
		t2 := time.Unix(timestamp2, 0)

		result.Annotations["description"] =
			fmt.Sprintf(
				"threshold: (gt %.2f%s || lt -%.2f%s), VALUE: %.2f%s, detail: %s > %sMb/s, %s > %sMb/s",
				rule.THigh, rule.Unit, rule.TLow, rule.Unit, alert.Value, alert.Unit, t1.Format(time.RFC3339), cpv1[1], t2.Format(time.RFC3339), cpv2[1],
			)
	} else if alert.Code == "0303" {
		result.Labels["to_customer"] = "yes"
		result.Annotations["description"] = fmt.Sprintf("threshold: gt %.2f%s, VALUE: %.2f%s", rule.THigh, rule.Unit, alert.Value, alert.Unit)
	} else if alert.Code == "0401" {
		result.Annotations["description"] = fmt.Sprintf("threshold: gt %.2f%s, VALUE: %.2f%s", rule.THigh, rule.Unit, alert.Value, alert.Unit)
	} else if alert.Code == "0701" {
		result.Annotations["description"] = fmt.Sprintf("threshold: lt %.2f%s, VALUE: %.2f%s", rule.TLow, rule.Unit, alert.Value, alert.Unit)
	}

	return result
}

func getAlerting() []Alerting {

	results := []Alerting{}

	if err := db.Raw(
		`SELECT * FROM fm_alarminfo AS fa WHERE fa.fm_latelytime >= date_add(now(),INTERVAL - 20 MINUTE)`).Scan(&results).Error; err != nil {
		log.Printf("Query alerting err: %v\n", err)
		return nil
	}

	return results
}

func getAlertingRule() []AlertingRule {

	results := []AlertingRule{}

	if err := db.Raw(
		`SELECT
		rfmd.domain_id AS domain_id,
		rfmd.domain_name AS domain,
		rfmr.id AS rule_id,
		rfmi.item_code AS rule_code,
		rfmi.item_name AS rule_name,
		rfmr.threshold_high AS threshold_high,
		rfmr.threshold_low AS threshold_low,
		rfmr.unit AS unit,
		rfmr.attention_threshold AS attention_threshold,
		rfmr.ci_id AS ci_id,
		rfmr.notify_mail AS notify_mail,
		rfmr.res_code AS response_code,
		rfmr.diff_type AS diff_type 
	FROM
		real_flux_monitor_rule rfmr
		LEFT JOIN real_flux_monitor_item rfmi ON rfmr.item_id = rfmi.item_code
		LEFT JOIN real_flux_monitor_domain rfmd ON rfmr.id = rfmd.rule_id
	WHERE rfmr.status = ?`, 1).Scan(&results).Error; err != nil {
		log.Printf("Query alerting rule err: %v\n", err)
		return nil
	}

	return results
}
